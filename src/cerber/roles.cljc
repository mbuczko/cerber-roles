(ns cerber.roles
  (:require
   [cerber.impl.roles :refer :all]
   #?(:clj [cerber.oauth2.context])))

(defn strings->permissions
  "Transforms collections of stringified permissions into set of `Permission`s."

  [strings]
  (into #{} (map make-permission strings)))

(defn permissions->strings
  "Transform collections of `Permission`s into their stringified versions."

  [permissions]
  (map #(let [{:keys [domain action entities]} %]
          (-> (str domain ":" action)
              (cond-> entities (str ":" entities))))
       permissions))

(defn implied-by? [permission permissions]
  (let [p (make-permission permission)]
    (contains-matching-permission? permissions p)))

(defn has-role?
  "Returns true if principal has given role assigned.
  Returns false otherwise."

  [role principal]
  (let [roles (:roles principal)]
    (and roles (contains? roles role))))

(defn has-permission?
  "Returns true if principal has given permission assigned.
  Returns false otherwise."

  [p principal]
  (let [{:keys [permissions]} principal]
    (and p permissions (implied-by? p permissions))))

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
