(ns cerber.impl.roles
  (:require [clojure.set :refer [union intersection]]))

(defrecord Permission [domain action entities wildcard-permission? wildcard-action?])

(defn wildcard-str? [str]
  (= str "*"))

(defn role-str? [str]
  (and str (.contains str "/")))

(defn make-permission
  "Builds a `Permission` based on its stringified form like 'user:write'."

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

(defn merge-set [coll e]
  (let [c (or coll (hash-set))]
    (if e (conj c e) c)))

(defn update-resolution-map
  [kv role s]
  (cond-> kv
    (role-str? s)
    (update-in [:dependencies role] conj s)

    true
    (update-in [:mapping role] merge-set (make-permission s))))

(defn roles-reducer
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

#?(:clj (defn update-principals-roles-permissions
          "Updates principal's roles and permissions according to following rules:

  - if a client is given (which assumes client-originated request) roles are calculated
  based on client's scopes-to-roles transitions map and intersected with principal's own roles.
  Next, based on resulting roles, permissions are calculated and assigned finally to principal.

  - if no client is given (which assumes user-originated request) principal's roles stay
  untouched. Permissions are being calculated and merged with own principal's ones (if any).

  General idea behind these two rules is: when client's scopes are available use them to deduce
  roles and permissions, otherwise use own principal's roles to calculate final permissions."

          [principal client roles-mapping transitions]
          (let [roles (:roles principal)
                perms (:permissions principal)]

            (if client
              (let [client-roles (->> (:scopes client)
                                      (mapcat transitions)
                                      (set)
                                      (intersection roles))]

                (assoc principal
                       :roles client-roles
                       :permissions (roles->permissions client-roles roles-mapping)))

              (assoc principal
                     :permissions (into (roles->permissions roles roles-mapping) perms))))))
