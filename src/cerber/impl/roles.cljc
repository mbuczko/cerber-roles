(ns cerber.impl.roles
  "Implementation of roles- and permissions API functions.
  These functions may be changed/reimplemented in a future releases."

  (:require [clojure.set :refer [union intersection]]
            [clojure.string :as str]))

(defrecord Permission [domain actions])

(defn role-str?
  [str]
  (and str (.contains str "/")))

(defn decompose-str
  [p]
  (when p
    (let [arr (.split (.trim p) ":")]
      (when (or (= -1 (.indexOf p ":"))
                (=  2 (count arr)))
        arr))))

(defn make-permission
  "Builds a `Permission` based on colon-separated string, like \"user:write\".

  Permission may be exact one, may have wildcard-action or have both domain
  and actions wildcarded. In this case a `wildcard?` is set to true and both
  fields contain a wildcard symbol \"*\" as a value."

  [p]
  (let [[domain a-list] (decompose-str p)
        wildcard? (or (= p "*")
                      (= domain a-list "*"))]
    (when (or wildcard? (seq domain))
      (let [actions (when (and a-list (not= "*" a-list))
                      (into #{} (.split a-list ",")))]
        (->Permission (or domain "*")
                      (or actions "*"))))))

(defn merge-set
  [coll e]
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
  role-to-permissions, later one acts as roles dependency graph (as roles can be nested)."

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
    (if (= "*" s)
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
  "Walks through role-to-permissions mappings unrolling every nested
  role with flat set of permissions."

  [{:keys [mapping dependencies] :as roles}]
  (reduce (fn [reduced [r _]]
            (let [perms (find-dependent-permissions r roles)]
              (update reduced r union perms)))
          mapping
          dependencies))

(defn contains-action?
  [actions a]
  (or (= "*" actions)
      (contains? actions a)
      (seq (intersection actions a))))

(defn contains-exact-permission?
  [permissions p]
  (contains? permissions p))

(defn contains-domain-action?
  [permissions {:keys [domain actions]}]
  (some #(and (or (= "*" (:domain %1))
                  (= domain (:domain %1)))
              (contains-action? (:actions %1) actions))
        permissions))

(defn contains-wildcard-permission?
  [permissions]
  (some :wildcard? permissions))

(defn contains-matching-permission?
  [permissions p]
  (or (contains-exact-permission? permissions p)
      (contains-domain-action? permissions p)))

(defn roles->permissions*
  "Unrolls roles into corresponding set of permissions."

  [roles roles-mapping]
  (reduce (fn [coll role] (into coll (get roles-mapping role)))
          #{}
          roles))

(def roles->permissions
  (memoize roles->permissions*))

#?(:clj (defn update-subject-roles-permissions
          "Updates subject's roles and permissions according to following rules:

  - if a client is given (which assumes client-originated request) roles are calculated
  based on client's scopes-to-roles transitions map and intersected with subject's own roles.
  Next, based on resulting roles, permissions are calculated and assigned finally to subject.

  - if no client is given (which assumes user-originated request) subject's roles stay
  untouched. Permissions are being calculated and merged with own subject's ones (if any).

  General idea behind these two rules is: when client's scopes are available use them to deduce
  roles and permissions, otherwise use own subject's roles to calculate final permissions."

          [subject client roles-mapping transitions]
          (when subject
            (let [roles (:roles subject)
                  perms (into (roles->permissions roles roles-mapping)
                              (:permissions subject))]

              (if client
                (let [client-roles (set (mapcat transitions (:scopes client)))
                      client-perms (roles->permissions client-roles roles-mapping)]

                  (assoc subject
                         :roles (intersection roles client-roles)
                         :permissions (intersection perms client-perms)))

                (assoc subject :permissions perms))))))
