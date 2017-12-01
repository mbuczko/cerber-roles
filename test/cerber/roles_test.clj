(ns cerber.roles-test
  (:require [cerber.roles :refer [init-roles has-permission has-role implied-by? make-permission]]
            [clojure.test :refer :all]))

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


(deftest create-permissions
  (testing "exact permission"
    (let [permission (make-permission "user:read")]
      (is (= (:domain permission) "user"))
      (is (= (:actions permission) "read"))
      (is (not (:wildcard-action? permission)))
      (is (not (:wildcard-permission? permission)))))

  (testing "wildcard action"
    (let [permission (make-permission "user:*")]
      (is (= (:domain permission) "user"))
      (is (= (:actions permission) "*"))
      (is (:wildcard-action? permission))
      (is (not (:wildcard-permission? permission)))))

  (testing "wildcard permission"
    (let [permission (make-permission "*")]
      (is (= (:domain permission) "*"))
      (is (= (:actions permission) "*"))
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
  (testing "principal with a role"
    (let [principal {:roles #{"user/read" "user/write"}}]
      (is (has-role "user/read" principal))
      (is (not (has-role "user/edit" principal)))))

  (testing "principal with a permission"
    (let [principal {:roles #{"user/read" "timeline/edit"}
                     :permissions #{(make-permission "project:read")
                                    (make-permission "contacts:*")}}]
      (is (has-permission "project:read"   principal roles))
      (is (has-permission "timeline:read"  principal roles))
      (is (has-permission "contacts:read"  principal roles))
      (is (has-permission "contacts:write" principal roles))
      (is (not (has-permission "project:write" principal roles))))))
