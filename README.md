# Roles and permissions

This simple library fills in the gap between OAuth2 scopes and role-based access control usually used to protect user resources.

As OAuth2 specification does not describe directly how OAuth scopes translate to roles and permissions, this code has been separated from
[Cerber OAuth2 Provider](https://github.com/mbuczko/cerber-oauth2-provider) implementation and published as optional plugin-in that makes
scopes and roles/permissions mix and matching a bit easier.

This solution conceptually bases on [thulmann/permissions](https://github.com/tuhlmann/permissions) and exposes very similar API.

## Anatomy of Permission

A permission consists of three parts: a domain, an action and a set of entities, all joined with ':'. Example: `user:read:1234,5678`.

A few interesting cases may appear here:

 - no particular entities mentioned: action is allowed on all entities. Example: `user:read`.
 - wildcard action: any action within given domain is allowed. Example: `user:*`
 - wildcard permission: any action on any domain is allowed. Example: `*`

## Anatomy of Role

Similar to permission, role consists of 2 parts: domain and a name, both joined with '/'.
It is used to group multiple permissions together in a simple mapping, like following:

``` clojure
{"user/all"      #{"user:read", "user:write"}
 "project/read"  #{"project:read"}}
```

Interesting thing here is that role may also map to wildcard actions and other roles, exact or wildcard ones:

``` clojure
{"user/edit     #{"user:read", "user:write"}
 "project/all"  #{"project:*", "timeline:*"}
 "admin/company #{"user/*", "project/*"}
 "admin/all     "*"}
```

# API

`(init-roles [roles-map])`

Initializes roles-to-permissions mapping.

Initialized mapping has no longer nested roles (they get unrolled with corresponding permissions).

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

Returns true if `role` matches any of principal's set of `:roles` 

``` clojure
(has-role {:roles #{"user/read" "user/write"}} "user/write")
```

`(has-permission [principal permission])`

Returns true if `permission` matches any of principal's set of `:permissions`.
Permissions can be exact (eg. `user:write`) or wildcard ones (`user:*`).

``` clojure
(has-permission {:permissions #{(make-permission "project:read")
                                (make-permission "contacts:*")}}
                "contacts:write")
```

