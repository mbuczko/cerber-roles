(ns cerber.roles
  "An API with all the functions for roles- and permissions creation and assertion."

  (:require
   [cerber.impl.roles :refer :all]
   [clojure.set :as set]
   #?(:clj [cerber.oauth2.context])))

(defn strings->permissions
  "Decomposes collections of colon-separated permission strings into set of `Permission`s."

  [strings]
  (into #{} (map make-permission strings)))

(defn implied-by? [permission permissions]
  (let [p (make-permission permission)]
    (contains-matching-permission? permissions p)))

(defn has-role?
  "Returns true if subject has given role assigned, returns false otherwise."

  [subject role]
  (let [roles (:roles subject)]
    (and roles (contains? roles role))))

(defn has-permission?
  "Returns true if subject holds given permission, returns false otherwise."

  [subject permission]
  (let [{:keys [permissions]} subject]
    (and permission permissions (implied-by? permission permissions))))

#?(:clj (defn init-roles
          "Returns a mapping between roles and set of permissions. Nested roles,
  that means ones which map to other roles, are unrolled and flattened into
  union of respective permissions."

          [roles]
          (unroll-roles
           (reduce-kv roles-reducer {} roles))))

;; ring middleware

#?(:clj (defn populate-roles-and-permissions
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
                         :roles (set/intersection roles client-roles)
                         :permissions (set/intersection perms client-perms)))

                (assoc subject :permissions perms))))))

#?(:clj (defn wrap-permissions
          "Sets up user's permissions and roles."

          [handler roles-mapping scopes->roles]
          (fn [req]
            (handler (let [client (:cerber.oauth2.context/client req)]
                       (update req
                               :cerber.oauth2.context/user
                               populate-roles-and-permissions
                               client
                               roles-mapping
                               scopes->roles))))))
