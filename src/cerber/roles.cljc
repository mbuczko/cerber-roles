(ns cerber.roles
  (:require
   #?(:clj [cerber.oauth2.context])
   [clojure.set :refer [union intersection]]))

(defrecord Permission [domain action entities wildcard-permission? wildcard-action?])

(defn wildcard-str? [str]
  (= str "*"))

(defn role-str? [str]
  (and str (.contains str "/")))

(defn make-permission
  "Build a `Permission` based on its stringified form like 'user:write'."

  [p]
  (let [[domain action entities] (.split p ":")
        wildcard? (wildcard-str? p)
        sanitized (and action (.trim action))]
    (when (or wildcard? (seq sanitized))
      (map->Permission
       {:domain   domain
        :entities entities
        :action   (or sanitized "*")
        :wildcard-permission? wildcard?
        :wildcard-action? (or wildcard? (wildcard-str? sanitized))}))))

(defn- merge-set [coll e]
  (let [c (or coll (hash-set))]
    (if e (conj c e) c)))

(defn- update-resolution-map
  [kv role s]
  (cond-> kv
    (role-str? s)
    (update-in [:dependencies role] conj s)

    true
    (update-in [:mapping role] merge-set (make-permission s))))

(defn- roles-reducer
  "Updates a map of :permissions and :dependencies, where first holds a mapping of
  role-to-permissions, latter one acts as roles dependency graph (as roles can be nested)."

  [reduced role s]
  (if (string? s)
    (update-resolution-map reduced role s)
    (loop [result reduced, roles-or-permissions s]
      (if-let [rp (first roles-or-permissions)]
        (recur
         (update-resolution-map result role rp)
         (rest roles-or-permissions))
        result))))

(defn permissions-by-role
  "Filters role-to-permissions mapping according to given role
  which can be exact or wildcard one. Returns list of [role permissions]."

  [mapping role]
  (let [[d s] (.split role "/")]
    (if (wildcard-str? s)
      (filter (fn [[k v]] (.startsWith k (str d "/"))) mapping)
      (list [role (get mapping role)]))))

(defn find-dependent-permissions
  [role {:keys [mapping dependencies]}]
  (loop [result nil, stack (get dependencies role)]
    (if-let [r (first stack)]
      (let [filtered (permissions-by-role mapping r)]
        (recur
         (concat result (map second filtered))
         (reduce #(concat %1 (get dependencies %2))
                 (rest stack)
                 (map first filtered))))
      (apply union result))))

(defn unroll-roles
  "Walks through role-to-permissions mappings unrolling every nested role.
  Returns same mapping with nested roles replaced by flat set of permissions."

  [{:keys [mapping dependencies] :as roles}]
  (reduce (fn [reduced [r _]]
            (let [perms (find-dependent-permissions r roles)]
              (update reduced r union perms)))
          mapping
          dependencies))

(defn contains-exact-permission?
  [permissions p]
  (contains? permissions p))

(defn contains-wildcard-permission?
  [permissions]
  (some :wildcard-permission? permissions))

(defn contains-wildcard-action?
  [permissions p]
  (let [domain (:domain p)]
    (some #(and (:wildcard-action? %1)
                (= domain (:domain %1)))
          permissions)))

(defn contains-matching-permission?
  [permissions p]
  (or (contains-exact-permission? permissions p)
      (contains-wildcard-action? permissions p)
      (contains-wildcard-permission? permissions)))

(defn roles->permissions*
  "Unrolls roles into corresponding set of permissions."

  [roles roles-mapping]
  (reduce (fn [coll role] (into coll (get roles-mapping role)))
          #{}
          roles))

(def roles->permissions
  (memoize roles->permissions*))

(defn implied-by? [permission permissions]
  (let [p (make-permission permission)]
    (contains-matching-permission? permissions p)))

;; API

(defn strings->permissions
  "Transforms collections of stringified permissions into set of `Permission`s."

  [strings]
  (into #{} (map make-permission strings)))

(defn permissions->strings
  "Transform collections of `Permission`s into their stringified versions."

  [permissions]
  (map #(let [{:keys [domain action entities]} %]
          (-> (str domain ":" action)
              (cond-> entities (str ":" entities))))
       permissions))

(defn has-role?
  "Returns true if principal has given role assigned.
  Returns false otherwise."

  [role principal]
  (let [roles (:roles principal)]
    (and roles (contains? roles role))))

(defn has-permission?
  "Returns true if principal has given permission assigned.
  Returns false otherwise."

  [p principal]
  (let [{:keys [permissions]} principal]
    (and p permissions (implied-by? p permissions))))

#?(:clj (defn init-roles
          "Returns a mapping between roles and set of permissions. Nested roles,
  that means ones which map to other roles, are unrolled and flattened into
  union of respective permissions."

          [roles]
          (unroll-roles
           (reduce-kv roles-reducer {} roles))))

   ;; ring middleware

#?(:clj (defn update-with-calculated-permissions
          "Updates principal's roles and permissions according to following rules:

  - if a client is given (which assumes client-originated request) roles are calculated
  based on client's scopes-to-roles transitions map and intersected with principal's roles.
  Next, based on roles, permissions are being calculated and finally assigned to principal.

  - if no client is given (which assumes user-originated request) principal's roles stay
  untouched. Permissions are being populated and merged with those already assigned."

          [principal client roles-mapping transitions]
          (let [roles (:roles principal)
                perms (:permissions principal)]

            (if client
              (let [roles (->> (:scopes client)
                               (mapcat transitions)
                               (set)
                               (intersection roles))]

                (assoc principal
                       :roles roles
                       :permissions (roles->permissions roles roles-mapping)))

              (assoc principal
                     :permissions (into (roles->permissions roles roles-mapping) perms))))))

#?(:clj (defn wrap-permissions
          "Sets up user's permissions and roles."

          [handler roles-mapping transitions]
          (fn [req]
            (handler (let [client (:cerber.oauth2.context/client req)]
                       (update req
                               :cerber.oauth2.context/user
                               update-with-calculated-permissions
                               client
                               roles-mapping
                               transitions))))))
