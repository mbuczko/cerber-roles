(ns cerber.impl.roles
  (:require [cerber.impl.permissions :refer [make-permission]]
            [weavejester.dependency :as dep]
            [clojure.set :as set]
            [clojure.string :as str]))

(defn role-str?
  [str]
  (and str (.contains str "/")))

(defn roles-by-domain
  [domain roles-names]
  (let [d (str domain "/")]
    (filter #(.startsWith % d) roles-names)))

(defn replace-wildcard-roles
  [roles-or-permissions roles-names]
  (loop [rops roles-or-permissions, result #{}]
    (if-let [role-or-perm (first rops)]
      (recur (rest rops)
             (if-not (role-str? role-or-perm)
               ;; permission
               (conj result role-or-perm)

               ;; role
               (let [[domain role] (.split role-or-perm "/")]
                 (assert (and domain role (not= "" domain)))
                 (if (= "*" role)
                   (into result (roles-by-domain domain roles-names))
                   (conj result role-or-perm)))))
      result)))

(defn unwind-wildcard-roles
  [roles]
  (when-let [roles-names (keys roles)]
    (reduce-kv (fn [m k v]
                 (assoc m k (replace-wildcard-roles
                             (if (string? v) (hash-set v) v)
                             roles-names)))
               {}
               roles)))

(defn add-dependencies
  [graph role-name roles]
  (reduce #(dep/depend %1 role-name %2) graph roles))

(defn build-dependency-graph
  [roles-kv]
  (loop [graph (dep/graph), roles roles-kv]
    (if-let [[role-name roles-or-permissions] (first roles)]
      (recur
       (add-dependencies graph role-name (filter role-str? roles-or-permissions))
       (rest roles))
      {:roles roles-kv
       :dependencies graph})))

(defn replace-with-permissions
  [roles-or-permissions roles-kv]
  (reduce (fn [result rop]
            (if (role-str? rop)
              (into result (roles-kv rop))
              (conj result (make-permission rop))))
          #{}
          roles-or-permissions))

(defn resolve-permissions
  [{:keys [roles dependencies]}]
  (let [deps (dep/topo-sort dependencies)              ;; roles that other roles depend on, sorted topologically
        diff (set/difference (set (keys roles)) deps)] ;; roles that no other roles depend on, thus not listed in dependencies
    (loop [sorted (concat deps diff), result {}]
      (if-let [role-name (first sorted)]
        (recur (rest sorted)
               (assoc result role-name (replace-with-permissions
                                        (roles role-name)
                                        result)))
        result))))

(defn unroll-roles
  "Walks through role-to-permissions mappings unrolling every nested
  role with flat set of permissions."

  [roles]
  (-> roles
      (unwind-wildcard-roles)
      (build-dependency-graph)
      (resolve-permissions)))

(defn roles->permissions*
  "Unrolls roles into corresponding set of permissions."

  [roles roles-mapping]
  (reduce (fn [coll role] (into coll (get roles-mapping role)))
          #{}
          roles))

(def roles->permissions
  (memoize roles->permissions*))

(defn populate-roles-and-permissions
  "Updates subject's roles and permissions according to following rules:

  - if a client is given (which assumes client-originated request) roles are calculated
  based on client's scopes-to-roles transitions map intersected with subject's own roles.
  Next, based on resulting roles, permissions are calculated and assigned finally to subject.

  - if no client is given (which assumes user-originated request) subject's roles stay
  untouched. Permissions are being calculated and merged with own subject's ones (if any).

  General idea behind these two rules is: when client's scopes are available use them to deduce
  roles and permissions, otherwise use subject's own roles to calculate final permissions."

  [subject client roles-mapping transitions]
  (when subject
    (let [roles (:roles subject)
          perms (into (roles->permissions roles roles-mapping)
                      (:permissions subject))]

      (if client
        (if transitions
          (let [client-roles (set (mapcat transitions (:scopes client)))
                client-perms (roles->permissions client-roles roles-mapping)]

            ;; client's roles and permissions calculated.
            ;; need to intersect them with user's original privileges.
            (assoc subject
                   :roles (set/intersection roles client-roles)
                   :permissions (set/intersection perms client-perms)))

          ;; no roles-to-scopes transitions provided.
          ;; clients should have empty roles and permissions in this case
          ;; as scopes cannot be translated into anything meaningful.
          (assoc subject
                 :roles (clojure.lang.PersistentHashSet/EMPTY)
                 :permissions (clojure.lang.PersistentHashSet/EMPTY)))

        ;; not a client's request.
        ;; assign user his own permissions (calculated upon roles)
        (assoc subject :permissions perms)))))
