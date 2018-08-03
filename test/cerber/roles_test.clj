(ns cerber.roles-test
  (:require [cerber.impl.roles :refer [make-permission update-subject-roles-permissions]]
            [cerber.roles :refer :all]
            [clojure.test :refer :all]))

;; a mapping between roles and sets of permissions.
;; `init-roles` replaces all the nested roles with flat set of permissions.

(def mapping {"admin"           "*"
              "user/super"      "user:*"
              "user/all"        #{"user:read" "user:write"}
              "unit/read"       #{"user:read"}
              "manager/read"    #{"account:read"}
              "manager/super"   #{"account:read" "account:write" "account:edit" "account:delete"}
              "manager/write"   "unit/*"
              "contact/read"    #{"contact:read"}
              "department/all"  #{"contact/read" "user/*" "project:read"}
              "department/edit" "manager/*"})

;; client's scopes-to-roles mapping used by ring middleware

(def scopes->roles {"public:read" #{"unit/read" "manager/read"}})

(deftest create-permissions
  (testing "exact permission"
    (let [permission (make-permission "user:read")]
      (is (= "user" (:domain permission)))
      (is (contains? (:actions permission) "read"))))

  (testing "exact permission with multiple actions"
    (let [permission (make-permission "user:read,write")]
      (is (= "user" (:domain permission)))
      (is (contains? (:actions permission) "read"))
      (is (contains? (:actions permission) "write"))))

  (testing "wildcard action"
    (let [permission (make-permission "user")]
      (is (= "user" (:domain permission)))
      (is (= "*" (:actions permission)))))

  (testing "wildcard domain"
    (let [permission (make-permission "*:write")]
      (is (= "*" (:domain permission)))
      (is (contains? (:actions permission) "write"))))

  (testing "explicitly wildcarded action"
    (let [permission (make-permission "user:*")]
      (is (= "user" (:domain permission)))
      (is (= "*" (:actions permission)))))

  (testing "wildcard permission"
    (let [permission (make-permission "*")]
      (is (= "*" (:domain permission)))
      (is (= "*" (:actions permission)))))

  (testing "explicitly wildcarded permission"
    (let [permission (make-permission "*:*")]
      (is (= "*" (:domain permission)))
      (is (= "*" (:actions permission)))))

  (testing "invalid permissions"
    (is (nil? (make-permission nil)))
    (is (nil? (make-permission "")))
    (is (nil? (make-permission " ")))
    (is (nil? (make-permission "user:")))
    (is (nil? (make-permission "user: ")))
    (is (nil? (make-permission ":")))
    (is (nil? (make-permission ":read")))
    (is (nil? (make-permission "  :write")))))

(deftest checking-permissions
  (testing "exact permission"
    (let [permissions #{(make-permission "contact:read")}]
      (is (implied-by? "contact:read" permissions))
      (is (not (implied-by? "contact:delete" permissions)))
      (is (not (implied-by? "contact:write" permissions)))))

  (testing "exact permission with multiple actions"
    (let [permissions #{(make-permission "contact:read,write")}]
      (is (implied-by? "contact:read" permissions))
      (is (implied-by? "contact:write" permissions))
      (is (implied-by? "contact:read,write" permissions))
      (is (not (implied-by? "contact:delete" permissions)))))

  (testing "wildcard-action permission"
    (let [permissions #{(make-permission "user")}]
      (is (implied-by? "user:delete" permissions))
      (is (not (implied-by? "contact:delete" permissions)))))

  (testing "wildcard-domain permission"
    (let [permissions #{(make-permission "*:read,write")}]
      (is (implied-by? "contact:write" permissions))
      (is (implied-by? "user:write" permissions))
      (is (implied-by? "user:delete,write" permissions))
      (is (not (implied-by? "contact:delete" permissions)))))

  (testing "wildcard permission"
    (let [permissions #{(make-permission "*")}]
      (is (implied-by? "user:delete" permissions))
      (is (implied-by? "contact:write" permissions)))))

(deftest unrolled-roles
  (let [roles (init-roles mapping)]
    (testing "role with nested roles contains exact permission"
      (let [permissions (roles "department/all")]
        (is (implied-by? "project:read" permissions))
        (is (implied-by? "contact:read" permissions))
        (is (not (implied-by? "contact:write" permissions)))))

    (testing "role with nested wildcard role contains permission of the same domain"
      (let [permissions (roles "department/all")]
        (is (implied-by? "user:read" permissions))
        (is (implied-by? "user:write" permissions))
        (is (implied-by? "user:delete" permissions))
        (is (not (implied-by? "employee:read" permissions)))
        (is (not (implied-by? "account:read" permissions)))))

    (testing "role with wildcard permission only contains permission of the same domain"
      (let [permissions (roles "department/edit")]
        (is (implied-by? "account:delete" permissions))
        (is (not (implied-by? "contact:read" permissions)))))

    (testing "double nested roles"
      (is (implied-by? "user:read" (roles "department/edit"))))))

(deftest subject-permissions
  (testing "subject with a roles"
    (let [subject {:roles #{"user/read" "user/write"}}]
      (is (has-role? subject "user/read"))
      (is (not (has-role? subject "user/edit")))))

  (testing "subject with a permissions"
    (let [subject {:permissions #{(make-permission "project:read")
                                  (make-permission "contact:*")}}]
      (is (has-permission? subject "project:read"))
      (is (has-permission? subject "contact:read"))
      (is (has-permission? subject "contact:write"))
      (is (not (has-permission? subject "project:write"))))))

(deftest subject-updated-with-middleware
  (let [roles   (init-roles mapping)
        subject {:roles #{"unit/read"}
                 :permissions #{(make-permission "project:read")}}]

    (testing "client provided, scopes map to roles exceeding subject's original roles"
      (let [updated (update-subject-roles-permissions
                     subject {:scopes ["public:read"]} roles {"public:read" #{"unit/read" "manager/read"}})]
        (is (= #{"unit/read"} (:roles updated)))
        (is (= #{(make-permission "user:read")} (:permissions updated)))))

    (testing "client provided with empty scopes"
      (let [updated (update-subject-roles-permissions subject #{} roles scopes->roles)]
        (is (= #{} (:roles updated)))
        (is (= #{} (:permissions updated)))))

    (testing "client not provided, some permission already assigned to subject"
      (let [updated (update-subject-roles-permissions subject nil roles scopes->roles)]
        (is (= #{"unit/read"} (:roles updated)))
        (is (= #{(make-permission "user:read")
                 (make-permission "project:read")} (:permissions updated)))))))
