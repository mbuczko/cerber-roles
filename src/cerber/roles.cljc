(ns cerber.roles
  "An API with all the functions for roles- and permissions creation and assertion."

  (:require
   [cerber.impl.roles :refer :all]
   #?(:clj [cerber.oauth2.context])))

(defn strings->permissions
  "Decomposes collections of colon-separated permission strings
  into set of `Permission`s."

  [strings]
  (into #{} (map make-permission strings)))

(defn permissions->strings
  "Serializes set of `Permission`s into colon-separated permission strings."

  [permissions]
  (map #(let [{:keys [domain action]} %]
          (str domain ":" action))
       permissions))

(defn implied-by? [permission permissions]
  (let [p (make-permission permission)]
    (contains-matching-permission? permissions p)))

(defn has-role?
  "Returns true if principal has given role assigned, returns false otherwise.

  Role is a slash-separated pair \"domain/name\"."

  [principal role]
  (let [roles (:roles principal)]
    (and roles (contains? roles role))))

(defn has-permission?
  "Returns true if principal holds given permission, returns false otherwise.

  Permission is a colon-separated pair \"domain:action\"."

  [principal permission]
  (let [{:keys [permissions]} principal]
    (and permission permissions (implied-by? permission permissions))))

#?(:clj (defn init-roles
          "Returns a mapping between roles and set of permissions. Nested roles,
  that means ones which map to other roles, are unrolled and flattened into
  union of respective permissions."

          [roles]
          (unroll-roles
           (reduce-kv roles-reducer {} roles))))

;; ring middleware

#?(:clj (defn wrap-permissions
          "Sets up user's permissions and roles."

          [handler roles-mapping scopes->roles]
          (fn [req]
            (handler (let [client (:cerber.oauth2.context/client req)]
                       (update req
                               :cerber.oauth2.context/user
                               update-principals-roles-permissions
                               client
                               roles-mapping
                               scopes->roles))))))
