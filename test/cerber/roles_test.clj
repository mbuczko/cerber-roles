(ns cerber.roles-test
  (:require [cerber.impl.roles :refer [populate-roles-and-permissions]]
            [cerber.impl.permissions :refer [wildcard-action? wildcard-domain?]]
            [cerber.roles :refer [init-roles make-permission intersect-permissions implied-by? has-role? has-permission?]]
            [clojure.test :refer [deftest testing is]]))


;; a mapping between roles and sets of permissions.
;; `init-roles` replaces all the nested roles with flat set of permissions.

(def mapping {:user/admin      "*"
              :user/default    #{"user:read" "user:write"}
              :user/moderator  #{"post:delete"}
              :unit/read       #{"user:read"}
              :manager/read    #{"account:read"}
              :manager/super   #{"account:read" "account:write" "account:edit" "account:delete"}
              :manager/write   :unit/*
              :contact/read    #{"contact:read"}
              :contact/write   #{"contact:write" "contact:delete"}
              :department/all  #{:contact/* "project:read"}
              :department/edit :manager/*})

(def circular {:user/admin :manager/super
               :manager/super :user/admin})

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
      (is (wildcard-action? permission))))

  (testing "wildcard domain"
    (let [permission (make-permission "*:write")]
      (is (wildcard-domain? permission))
      (is (contains? (:actions permission) "write"))))

  (testing "explicitly wildcarded action"
    (let [permission (make-permission "user:*")]
      (is (= "user" (:domain permission)))
      (is (wildcard-action? permission))))

  (testing "wildcard permission"
    (let [permission (make-permission "*")]
      (is (wildcard-domain? permission))
      (is (wildcard-action? permission))))

  (testing "explicitly wildcarded permission"
    (let [permission (make-permission "*:*")]
      (is (wildcard-domain? permission))
      (is (wildcard-action? permission))))

  (testing "invalid permissions"
    (is (nil? (make-permission nil)))
    (is (nil? (make-permission "")))
    (is (nil? (make-permission " ")))
    (is (nil? (make-permission "user:")))
    (is (nil? (make-permission "user: ")))
    (is (nil? (make-permission ":")))
    (is (nil? (make-permission ":read")))
    (is (nil? (make-permission "  :write")))))

(deftest permissions-matching
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
      (is (not (implied-by? "user:delete,write" permissions)))
      (is (not (implied-by? "contact:delete" permissions)))))

  (testing "wildcard permission"
    (let [permissions #{(make-permission "*")}]
      (is (implied-by? "user:delete" permissions))
      (is (implied-by? "contact:write" permissions)))))

(deftest permissions-intersections
  (letfn [(has? [coll p]
            (contains? coll (make-permission p)))
          (intersect [p1 p2]
            (intersect-permissions [(make-permission p1)]
                                   [(make-permission p2)]))]

    (testing "exact domain, exact actions"
      (is (has?   (intersect "doc:read,write" "doc:read")        "doc:read"))
      (is (has?   (intersect "doc:read,write" "doc:read,create") "doc:read"))
      (is (empty? (intersect "doc:read,write" "doc:create")))
      (is (empty? (intersect "doc:read,write" "ws:read"))))

    (testing "exact domain, wildcard actions"
      (is (has?   (intersect "doc:read,write" "doc:*")  "doc:read,write"))
      (is (empty? (intersect "doc:read,write" "ws:*")))
      (is (has?   (intersect "doc:*" "doc:read,write")  "doc:read,write"))
      (is (empty? (intersect "doc:*" "ws:read,write"))))

    (testing "wildcard domain, exact actions"
      (is (has?   (intersect "*:read,write" "ws:read")         "ws:read"))
      (is (empty? (intersect "*:read,write" "ws:create")))
      (is (has?   (intersect "*:read,write" "ws:read,create")  "ws:read"))
      (is (empty? (intersect "*:read,write" "*:create")))
      (is (empty? (intersect "doc:read,write" "*:create")))
      (is (has?   (intersect "doc:read,write" "*:read,create") "doc:read")))

    (testing "wildcard domain, wildcard actions"
      (is (has?   (intersect "doc:*" "*:read,write") "doc:read,write"))
      (is (has?   (intersect "doc:*" "*:*")          "doc:*"))
      (is (has?   (intersect "doc:read,write" "*:*") "doc:read,write"))
      (is (has?   (intersect "*:read,write" "*:*")   "*:read,write"))
      (is (has?   (intersect "*:*" "doc:read,write") "doc:read,write"))
      (is (has?   (intersect "*:*" "doc:*")          "doc:*"))
      (is (has?   (intersect "*:*" "*:write")        "*:write"))
      (is (has?   (intersect "*:*" "*:*")            "*:*")))

    (testing "intersection of multiple permissions"
      (let [result (intersect-permissions [(make-permission "document:read,write")
                                           (make-permission "workspace:create")
                                           (make-permission "document:delete,create")]
                                          [(make-permission "*:create,delete")])]

        (is (implied-by? "document:create" result))
        (is (implied-by? "document:delete" result))
        (is (implied-by? "workspace:create" result))))))

(deftest roles-unrolling
  (let [roles (init-roles mapping)]
    (testing "simple role that no other role depends on"
      (is (implied-by? "post:delete" (roles :user/moderator))))

    (testing "role with nested roles contains exact permission"
      (let [permissions (roles :department/all)]
        (is (implied-by? "project:read" permissions))
        (is (implied-by? "contact:read" permissions))
        (is (not (implied-by? "account:read" permissions)))))

    (testing "role with nested wildcard role contains permission of the same domain"
      (let [permissions (roles :department/all)]
        (is (implied-by? "contact:read" permissions))
        (is (implied-by? "contact:write" permissions))
        (is (implied-by? "contact:delete" permissions))
        (is (not (implied-by? "employee:read" permissions)))
        (is (not (implied-by? "account:read" permissions)))))

    (testing "role with wildcard permission only contains permission of the same domain"
      (let [permissions (roles :department/edit)]
        (is (implied-by? "account:delete" permissions))
        (is (not (implied-by? "contact:read" permissions)))))

    (testing "double nested roles"
      (is (implied-by? "user:read" (roles :department/edit))))

    (testing "circular dependencies"
      (is (thrown-with-msg? Exception
                            #"Circular dependency between :manager/super and :user/admin"
                            (init-roles circular))))))

(deftest subject-with-roles-and-permissions
  (testing "roles are stored in set"
    (let [subject (:roles [:user/read :user/write])]
      (is (thrown? AssertionError (has-role? subject :user/read)))))

  (testing "subject has matching roles"
    (let [subject {:roles #{:user/read :user/write}}]
      (is (has-role? subject :user/read))
      (is (not (has-role? subject :user/edit)))))

  (testing "subject has matching permissions"
    (let [subject {:permissions #{(make-permission "project:read")
                                  (make-permission "contact:*")}}]
      (is (has-permission? subject "project:read"))
      (is (has-permission? subject "contact:read"))
      (is (has-permission? subject "contact:write"))
      (is (not (has-permission? subject "project:write"))))))

(deftest subject-updated-with-middleware
  (let [roles   (init-roles mapping)
        subject {:roles #{:unit/read}
                 :permissions #{(make-permission "project:read")}}]

    (testing "client provided, scopes map to roles exceeding subject's original roles"
      (let [updated (populate-roles-and-permissions
                     subject {:scopes ["public:read"]} roles {"public:read" #{:unit/read :manager/read}})]
        (is (= #{:unit/read} (:roles updated)))
        (is (= #{(make-permission "user:read")} (:permissions updated)))))

    (testing "client provided with empty scopes"
      (let [updated (populate-roles-and-permissions subject #{} roles scopes->roles)]
        (is (empty? (:roles updated)))
        (is (empty? (:permissions updated)))))

    (testing "client not provided, some permission already assigned to subject"
      (let [updated (populate-roles-and-permissions subject nil roles scopes->roles)]
        (is (= #{:unit/read} (:roles updated)))
        (is (= #{(make-permission "user:read")
                 (make-permission "project:read")} (:permissions updated)))))))
