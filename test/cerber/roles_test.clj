(ns cerber.roles-test
  (:require [cerber.impl.roles :refer [make-permission update-principals-roles-permissions]]
            [cerber.roles :refer :all]
            [clojure.test :refer :all]))

;; a mapping between roles and sets of permissions.
;; `init-roles` replaces all the nested roles with corresponding permissions.

(def roles (init-roles {"user/admin"    "user:*"
                        "user/all"      #{"user:read" "user:write"}
                        "admin/all"     "*"
                        "accounts/read" #{"user:read"}
                        "company/read"  #{"company:read"}
                        "company/super" #{"company:read" "company:write" "company:edit" "company:delete"}
                        "company/write" "accounts/*"
                        "contacts/read" #{"contacts:read"}
                        "timeline/edit" #{"timeline:edit" "timeline:read"}
                        "project/all"   #{"contacts/read" "user/*" "project:read"}
                        "project/edit"  "company/*"}))

;; client's scopes-to-roles mapping used by ring middleware

(def scopes->roles {"public:read" #{"accounts/read" "company/read"}})


(deftest create-permissions
  (testing "exact permission"
    (let [permission (make-permission "user:read")]
      (is (= (:domain permission) "user"))
      (is (= (:action permission) "read"))
      (is (not (:wildcard-action? permission)))
      (is (not (:wildcard-permission? permission)))))

  (testing "wildcard action"
    (let [permission (make-permission "user:*")]
      (is (= (:domain permission) "user"))
      (is (= (:action permission) "*"))
      (is (:wildcard-action? permission))
      (is (not (:wildcard-permission? permission)))))

  (testing "wildcard permission"
    (let [permission (make-permission "*")]
      (is (= (:domain permission) "*"))
      (is (= (:action permission) "*"))
      (is (:wildcard-action? permission))
      (is (:wildcard-permission? permission))))

  (testing "invalid actions"
    (is (nil? (make-permission "user")))
    (is (nil? (make-permission "user:")))
    (is (nil? (make-permission "user: ")))))

(deftest no-nested-roles
  (testing "role contains exact permission"
    (let [permissions (roles "contacts/read")]
      (is (implied-by? "contacts:read" permissions))
      (is (not (implied-by? "contacts:reads" permissions)))
      (is (not (implied-by? "contacts:write" permissions)))))

  (testing "role with wildcard action contains permission with same domain"
    (let [permissions (roles "user/admin")]
      (is (implied-by? "user:delete" permissions))
      (is (not (implied-by? "contacts:delete" permissions)))))

  (testing "role with wildcard permission contains every other permission"
    (let [permissions (roles "admin/all")]
      (is (implied-by? "user:delete" permissions))
      (is (implied-by? "foo:bar" permissions)))))

(deftest nested-roles
  (testing "role with nested roles contains exact permission"
    (let [permissions (roles "project/all")]
      (is (implied-by? "project:read" permissions))
      (is (implied-by? "contacts:read" permissions))
      (is (not (implied-by? "contacts:write" permissions)))))

  (testing "role with nested wildcard role contains permission of the same domain"
    (let [permissions (roles "project/all")]
      (is (implied-by? "user:read" permissions))
      (is (implied-by? "user:write" permissions))
      (is (implied-by? "user:foo" permissions))
      (is (not (implied-by? "users:read" permissions)))
      (is (not (implied-by? "company:read" permissions)))))

  (testing "role with wildcard permission only contains permission of the same domain"
    (let [permissions (roles "project/edit")]
      (is (implied-by? "company:delete" permissions))
      (is (not (implied-by? "contacts:read" permissions)))))

  (testing "double nested roles"
    (is (implied-by? "user:read" (roles "project/edit")))))

(deftest principal-permissions
  (testing "principal with a roles"
    (let [principal {:roles #{"user/read" "user/write"}}]
      (is (has-role? "user/read" principal))
      (is (not (has-role? "user/edit" principal)))))

  (testing "principal with a permissions"
    (let [principal {:permissions #{(make-permission "project:read")
                                    (make-permission "contacts:*")}}]
      (is (has-permission? "project:read"   principal))
      (is (has-permission? "contacts:read"  principal))
      (is (has-permission? "contacts:write" principal))
      (is (not (has-permission? "project:write" principal))))))

(deftest principal-updated-with-middleware
  (let [principal {:roles #{"accounts/read"}
                   :permissions #{(make-permission "project:read")}}]

    (testing "client provided, scopes map to roles exceeding principal's original roles"
      (let [updated (update-principals-roles-permissions
                     principal {:scopes ["public:read"]} roles {"public:read" #{"accounts/read" "company/read"}})]
        (is (= #{"accounts/read"} (:roles updated)))
        (is (= #{(make-permission "user:read")} (:permissions updated)))))

    (testing "client provided with empty scopes"
      (let [updated (update-principals-roles-permissions principal #{} roles scopes->roles)]
        (is (= #{} (:roles updated)))
        (is (= #{} (:permissions updated)))))

    (testing "client not provided, some permission already assigned to principal"
      (let [updated (update-principals-roles-permissions principal nil roles scopes->roles)]
        (is (= #{"accounts/read"} (:roles updated)))
        (is (= #{(make-permission "user:read")
                 (make-permission "project:read")} (:permissions updated)))))))
