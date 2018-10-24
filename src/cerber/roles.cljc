(ns cerber.roles
  "An API with all the functions for roles- and permissions creation and assertion."

  (:require [cerber.impl.permissions :as p]
            #?(:clj [cerber.impl.roles :as r])
            #?(:clj [cerber.oauth2.context])))


(defn implied-by? [permission permissions]
  (let [p (p/make-permission permission)]
    (p/contains-matching-permission? permissions p)))

(defn has-role?
  "Returns true if subject has given role assigned, returns false otherwise."

  [subject role]
  {:pre [(set? (:roles subject))]}
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
          (r/unroll-roles roles)))

;; ring middleware

#?(:clj (defn wrap-permissions
          "Sets up user's permissions and roles."

          [handler roles-mapping & [scopes->roles]]
          (fn [req]
            (handler (let [client (:cerber.oauth2.context/client req)]
                       (update req
                               :cerber.oauth2.context/user
                               r/populate-roles-and-permissions
                               client
                               roles-mapping
                               scopes->roles))))))
