[![Clojars Project](https://img.shields.io/clojars/v/cerber/cerber-roles.svg)](https://clojars.org/cerber/cerber-roles)

# Roles and permissions

This simple library fills in the gap between OAuth2 scopes and role-based access control usually used to protect user resources.

As OAuth2 specification does not describe directly how OAuth scopes translate to roles and permissions, this code has been separated from [Cerber OAuth2 Provider](https://github.com/mbuczko/cerber-oauth2-provider) implementation and published as optional plugin-in that makes scopes and roles/permissions mix and matching a bit easier.

## Anatomy of Permission

A permission consists of two parts: a _domain_ and _action_, both joined with colon, like `user:read`.

A few interesting cases may appear here:

 - wildcard action: any action within given domain is allowed. Example: `user:*`
 - wildcard permission: any action on any domain is allowed. Example: `*`

## Anatomy of Role

Similar to permission, role consists of two parts: _domain_ and a _name_, combined together with slash. Role is used to group multiple permissions, like following:

``` clojure
{"user/all"      #{"user:read", "user:write"}
 "project/read"  #{"project:read"}}
```

Role may map to wildcard actions and other roles too (exact or wildcards):

``` clojure
{"user/edit     #{"user:read", "user:write"}
 "project/all"  #{"project:*", "timeline:*"}
 "admin/company #{"user/*", "project/*"}
 "admin/all     "*"}
```

# Usage

Ok, so permissions and roles are already defined. Now, how to make them showing up in a request? 

A `wrap-permissions` middleware is an answer. It bases on a context set up by companion middleware - `wrap-authorized` (described [here](https://github.com/mbuczko/cerber-oauth2-provider)) and populates roles and permissions within authorized principal.

Let's walk through all the routes configuration basing on popular compojure to see how it works.

Cerber's routes go first:

```clojure
(require '[cerber.handlers])

(defroutes oauth2-routes
  (GET  "/authorize" [] cerber.handlers/authorization-handler)
  (POST "/approve"   [] cerber.handlers/client-approve-handler)
  (GET  "/refuse"    [] cerber.handlers/client-refuse-handler)
  (POST "/token"     [] cerber.handlers/token-handler)
  (GET  "/login"     [] cerber.handlers/login-form-handler)
  (POST "/login"     [] cerber.handlers/login-submit-handler))
```

Routes where we would like to have roles and permissions populated:

```clojure
(require '[cerber.oauth2.context :as ctx])

(defroutes user-routes
  (GET "/users/me" [] (fn [req]
                        {:status 200
                         :body {:client (::ctx/client req)
                                :user   (::ctx/user req)}})))
```

The crucial step is to apply cerber's middlewares:

```clojure
(require '[cerber.roles]
(require '[cerber.handlers]
(require '[compojure.core :refer [routes wrap-routes]]
(require '[ring.middleware.defaults :refer [api-defaults wrap-defaults]])

(defn api-routes
  [roles scopes->roles]
  (wrap-defaults
   (routes oauth2-routes (-> user-routes
                             (wrap-routes cerber.roles/wrap-permissions roles scopes->roles)
                             (wrap-routes cerber.handlers/wrap-authorized)))
   api-defaults))
   ```

Finally, let's combine all the routes with _roles_ and _scopes-to-roles_ mapping, assuming that OAuth2 client may have any of `resources:read`, `resources:write` or `resource:manage` scopes assigned:

```clojure
(def roles (cerber.roles/init-roles
             {"user/admin"   #{"photos:*" "comments:*"}
              "user/all"     #{"photos:read" "photos:write" "comments:read" "comments:write"}
              "user/limited" #{"photos:read" "comments:read"}}))

(def scopes->roles {"resources:read"   #{"user/limited"}
                    "resources:write"  #{"users/all"}
                    "resources:manage" #{"user/admin"}})

(def app-routes
  (routes
    (api-routes roles scopes->roles)
    oauth2-routes
    public-routes))
```
# How it works?

Looking at example above it's clear that entire mechanism comes down to 3 elements:

* _roles_, which for performance reasons get unrolled by `init-roles` to contain no nested entries
* _scopes->roles_ transition map which says how to translate an OAuth2 client's scope into a set of roles
* a middleware which takes _roles_ and _scopes->roles_ and populates permissions in a request

The only unknown is how middleware populates roles and permissions bearing in mind that two scenarios may happen:

1. Request is a web application originated, eg. user logged in and tries to view its own profile page.
   
   In this scenario, user populated into OAuth2 context by cerber's `wrap-authorized` middleware keeps its own roles (assigned at creation time) and gets all the permissions calculated upon these roles.

2. Request comes from an OAuth2 client.
   
   In this scenario OAuth2 client requests on behalf of user with approved set of scopes. Scopes are translated into roles (based on _scopes->roles_ mapping) and intersected with user's own roles.
   This is to avoid a situation where client's scopes translate into roles exceeding user's own roles. Calculated permissions are also intersected with user's permissions to avoid potential elevation.

# API

`(init-roles [roles-map])`

Initializes roles-to-permissions mapping.

Initialized mapping has no longer nested roles (they get unrolled with corresponding permissions).

`(has-role? [role principal])`

Returns true if `role` matches any of principal's set of `:roles` 

`(has-permission [permission principal])`

Returns true if `permission` matches any of principal's set of `:permissions`.
Permissions can be exact, eg. `user:write` or wildcard ones like `user:*`.

``` clojure
(def user {:roles #{"user/read" "user/write"}
           :permissions #{(make-permission "project:read")
                          (make-permission "contacts:*")}}

(has-permission user "contacts:write"))
(has-role user "user/write")
```


