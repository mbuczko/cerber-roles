# Roles and permissions

This is a simple library that handles user's roles and permissions, which is the missing piece of [Ceber OAuth2 Provider](https://github.com/mbuczko/cerber-oauth2-provider).
As OAuth2 specification does not describe directly how OAuth scopes translate to roles and permissions, this code has been separated from provider implementation and given as
optional plugin-in that makes scopes and roles/permissions mix and matching a bit easier.

This solution conceptually bases on [thulmann/permissions](https://github.com/tuhlmann/permissions) and exposes a few functions as an API.

`(init-roles [roles-map])`

Initializes roles-to-permissions mapping. Permissions can have a nested roles as well, initialization simplifies this notation by replacing roles with calculated permissions and
returns same mapping with no nested rules inside.

``` clojure
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
```

`(has-role [principal role])`

Returns true if `role` matches any of principal's `:roles`. 

``` clojure
(has-role {:roles #{"user/read" "user/write"}} "user/write")
```

`(has-permission [principal permission])`

Returns true if `permission` matches any of principal's `:permissions`.
Permissions can be exact (eg. `user:write`) or wildcard ones (`user:*`).

``` clojure
(has-permission {:permissions #{(make-permission "project:read")
                                (make-permission "contacts:*")}}
                "contacts:write")
```

