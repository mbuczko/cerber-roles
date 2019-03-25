(ns cerber.impl.roles
  (:require [cerber.impl.permissions :refer [make-permission]]
            [weavejester.dependency :as dep]
            [clojure.set :as set]))

(def decompose-role-key
  (juxt namespace name))

(defn replace-wildcard-roles
  [roles-or-permissions roles-names]
  (loop [rops roles-or-permissions, result #{}]
    (if-let [role-or-perm (first rops)]
      (recur (rest rops)
             (if (string? role-or-perm)
               ;; permission
               (conj result role-or-perm)

               ;; role
               (let [[domain role] (decompose-role-key role-or-perm)]
                 (if (= "*" role)
                   (into result (filter #(= domain (namespace %)) roles-names))
                   (conj result role-or-perm)))))
      result)))

(defn unwind-wildcard-roles
  [roles]
  (when-let [roles-names (keys roles)]
    (reduce-kv (fn [m k v]
                 (assoc m k (replace-wildcard-roles
                             (if (set? v) v (hash-set v))
                             roles-names)))
               {}
               roles)))

(defn add-dependency
  [graph role-name roles]
  (reduce #(dep/depend %1 role-name %2) graph roles))

(defn build-dependency-graph
  [roles-kv]
  (loop [graph (dep/graph)
         roles roles-kv]
    (if-let [[role-name roles-or-permissions] (first roles)]
      (recur
       (add-dependency graph role-name (filter keyword? roles-or-permissions))
       (rest roles))
      {:roles roles-kv
       :dependencies graph})))

(defn replace-with-permissions
  [roles-or-permissions roles-kv]
  (reduce (fn [result rop]
            (if (string? rop)
              (conj result (make-permission rop))
              (into result (roles-kv rop))))
          #{}
          roles-or-permissions))

(defn resolve-permissions
  [{:keys [roles dependencies]}]
  (let [;; roles that other roles depend on, sorted topologically
        deps (dep/topo-sort dependencies)

        ;; roles that do not depend on any other roles and no other
        ;; roles depend on them. independent roles are not listed
        ;; in `deps` so they are calculated here and concatenated
        ;; with dependencies afterwards.
        diff (set/difference (set (keys roles)) deps)]

    (loop [sorted (concat deps diff)
           result {}]
      (if-let [role-name (first sorted)]
        (recur (rest sorted)
               (assoc result role-name (replace-with-permissions
                                        (roles role-name)
                                        result)))
        result))))

(defn unroll-roles
  "Walks through `roles-mapping` unrolling every nested
  role with flat set of permissions."

  [roles-mapping]
  (-> roles-mapping
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
