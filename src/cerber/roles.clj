(ns cerber.roles
  (:require [clojure.set :refer [union]]))

(defrecord Permission [domain actions entities wildcard-permission? wildcard-action?])

(defn wildcard-str? [str]
  (= str "*"))

(defn role-str? [str]
  (and str (.contains str "/")))

(defn make-permission
  "Build a Permission based on its stringified form like 'user:write'."

  [perm-str]
  (let [[domain actions entities] (.split perm-str ":")
        wildcard? (wildcard-str? perm-str)
        sanitized (and actions (.trim actions))]
    (when (or wildcard? (seq sanitized))
      (map->Permission
       {:domain   domain
        :entities entities
        :actions  (or sanitized "*")
        :wildcard-permission? wildcard?
        :wildcard-action? (or wildcard? (wildcard-str? sanitized))}))))

(defn strings->permissions
  "Transforms collections of stringified permissions into set of Permissions."

  [strings]
  (into #{} (map make-permission strings)))

(defn- merge-set [coll e]
  (let [c (or coll (hash-set))]
    (if e (conj c e) c)))

(defn- update-internal-kv
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
    (update-internal-kv reduced role s)
    (loop [result reduced, roles-or-permissions s]
      (if-let [rp (first roles-or-permissions)]
        (recur
         (update-internal-kv result role rp)
         (rest roles-or-permissions))
        result))))

(defn permissions-by-role
  "Filters role-to-permissions mapping according to given role
  which can be exact or wildcard one. Returns list of [role permissions]."

  [mapping role]
  (let [[d s] (.split role "/")]
    (if (wildcard-str? s)
      (filter (fn [[k v]] (.startsWith k (str d "/"))) mapping)
      (list (vector role (get mapping role))))))

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
  "Walks through role-to-permissions mapping unrolling nested roles.
  Returns same mapping with all nested roles replaced by corresponding permissions."

  [{:keys [mapping dependencies] :as roles}]
  (reduce (fn [reduced [r _]]
            (let [perms (find-dependent-permissions r roles)]
              (update reduced r union perms)))
          mapping
          dependencies))

(defn contains-wildcard-permission?
  [permissions]
  (some :wildcard-permission? permissions))

(defn contains-wildcard-action?
  [permissions p]
  (let [domain (:domain p)]
    (some #(and (:wildcard-action? %1)
                (= domain (:domain %1)))
          permissions)))

(defn contains-exact-permission?
  [permissions p]
  (contains? permissions p))

(defn contains-matching-permission?
  [permissions p]
  (or (contains-exact-permission? permissions p)
      (contains-wildcard-action? permissions p)
      (contains-wildcard-permission? permissions)))

(defn contains-matching-permission-in-roles?
  [roles p mapping]
  (boolean (loop [rset roles]
             (when-let [r (first rset)]
               (or (contains-matching-permission? (mapping r) p)
                   (recur (rest rset)))))))
;; API

(defn implied-by? [perm-str permissions]
  (let [p (make-permission perm-str)]
    (contains-matching-permission? permissions p)))

(defn has-permission? [perm-str principal mapping]
  (when-let [{:keys [roles permissions]} principal]
    (let [p (make-permission perm-str)]
      (or (contains-matching-permission? permissions p)
          (contains-matching-permission-in-roles? roles p mapping)))))

(defn has-role? [role principal]
  (when-let [roles (:roles principal)]
    (contains? roles role)))

(defn init-roles
  "Returns a mapping between roles and set of Permissions based on initial
  roles-map. Nested roles (ones which map to other roles) get unrolled into
  union of respective permissions."

  [roles-map]
  (unroll-roles
   (reduce-kv roles-reducer {} roles-map)))
