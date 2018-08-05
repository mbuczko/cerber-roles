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
  [str]
  (when str
    (let [arr (.split (.trim str) ":")]
      (when (or (= -1 (.indexOf str ":"))
                (=  2 (count arr)))
        arr))))

(defn make-permission
  "Builds a `Permission` based on colon-separated string, like \"user:write\".

  Permission may be exact one, may have wildcard-action or have both domain
  and actions wildcarded. In this case a `wildcard?` is set to true and both
  fields contain a wildcard symbol \"*\" as a value."

  [^String p]
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
  [actions ^String a]
  (or (= "*" actions)
      (contains? actions a)
      (seq (intersection actions a))))

(defn contains-exact-permission?
  [permissions ^Permission p]
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
  [permissions ^Permission p]
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
