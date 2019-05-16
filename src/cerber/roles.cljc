(ns cerber.roles
  "An API with all the functions for roles- and permissions creation and assertion."

  (:require [cerber.impl.permissions :as p]
            #?(:clj [cerber.impl.roles :as r])))


(defn implied-by?
  "Returns resource `permission` if it's implied (has access to) by set of `permissions`.
  Returns falsey otherwise."

  [permission permissions]
  {:pre [(set? permissions)]}
  (let [p (p/build permission)]
    (p/contains-matching-permission? permissions p)))

(defn has-role?
  "Returns matching `role` if it's been found in `subject's` set of `:roles`.
  Returns falsey otherwise."

  [subject role]
  {:pre [(set? (:roles subject))]}
  ((:roles subject) role))

(defn has-permission?
  "Returns resource permission if it's implied by `subject`'s set of `:permissions`.
  Returns falsey otherwise."

  [subject permission]
  (implied-by? permission (:permissions subject)))

(defn make-permission
  "Builds a `Permission` based on string consisting of domain and actions,
  separated by colon, like \"user:read,write\".
  Permission may be exact one, have actions or domain (or both) wildcarded.

  Wildcard is denoted by \"*\", and means \"any\", so \"document:*\"
  permission can be read as \"any action on document\". "

  [^String str]
  (p/build str))

#?(:clj (defn roles->permissions
      "Returns set of permissions based on collection of `roles` and `mapping`
  returned by `init-roles` function."

      [roles mapping]
      (r/roles->permissions roles mapping)))

#?(:clj (defn intersect-permissions
         "Intersects 2 sets of permissions calculating their common domains and actions.
  For example, intersection of following permissions:

     [\"*:read,write\"] and [\"doc:read,create\"]

  results in [\"doc:read\"]."

         [coll1 coll2]
         (p/intersect coll1 coll2)))

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
