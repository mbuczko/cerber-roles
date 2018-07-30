[![Clojars Project](https://img.shields.io/clojars/v/cerber/cerber-roles.svg)](https://clojars.org/cerber/cerber-roles)

# Roles and permissions

This simple library fills in the gap between OAuth2 scopes and role-based access control, as OAuth2 specification does not explain directly how OAuth scopes translate into roles and permissions.

This code has been separated from [Cerber OAuth2 Provider](https://github.com/mbuczko/cerber-oauth2-provider) implementation and published as optional library which hopefully makes scopes and roles/permissions match a bit more natural.

## Anatomy of Permission

A permission model implemented by this library consists of two parts: a _domain_ and _action_, both joined with colon, like `user:read`.

This imposes two additional cases:

 - wildcard action: any action within given domain is allowed, eg: `user:*`
 - wildcard permission: any action on any domain is allowed: `*:*`, or simply `*`

For sake of clarity, no action on wildcard domain is permitted, so `*:write` is not a valid permission.

## Anatomy of Role

Similar to permission, role consists of two parts: _domain_ and a _name_, combined together with slash. Roles group multiple permissions in a mapping, like this:

``` clojure
"user/all"      #{"user:read", "user:write"}
"project/read"  #{"project:read"}
```

Roles may also map to wildcard actions and explicit or wildcard roles:

``` clojure
"admin/all     "*"                          ;; mapping to wildcard permission
"project/all"  #{"project:*", "timeline:*"} ;; mapping to wildcard-action permissions
"admin/company #{"user/*", "project/*"}     ;; mapping to other roles
```

# Usage

Once permissions and roles are already defined and bound together with carefully crafted mapping, how to make them showing up in a request? 

A `wrap-permissions` middleware is an answer. It bases on a context set up by companion middleware - `wrap-authorized` (described [here](https://github.com/mbuczko/cerber-oauth2-provider)) and populates roles and permissions of authorized principal.

Let's walk through routes configuration based on popular [Compojure](https://github.com/weavejester/compojure) to see how it works.

Cerber's OAuth2 routes go first:

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

Routes that should have roles and permission populated go next:

```clojure
(require '[cerber.oauth2.context :as ctx])

(defroutes user-routes
  (GET "/users/me" [] (fn [req]
                        {:status 200
                         :body {:client (::ctx/client req)
                                :user   (::ctx/user req)}})))
```

Now, the crucial step is to attach both cerber's middlewares:

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

Last step is to initialize routes with _roles_ and _scopes-to-roles_ mapping, here assuming that OAuth2 client may have any of `resources:read`, `resources:write` or `resource:manage` scopes assigned:

```clojure
(def roles (cerber.roles/init-roles
             {;; admin can do everything with photos and comments
              "user/admin"   #{"photos:*" "comments:*"}
              
              ;; user can read and write to photos and comments
              "user/all"     #{"photos:read" "photos:write" "comments:read" "comments:write"}
              
              ;; limited user can only read photos and comments
              "user/limited" #{"photos:read" "comments:read"}}))

(def scopes->roles {"resources:read"   #{"user/limited"}
                    "resources:write"  #{"users/all"}
                    "resources:manage" #{"user/admin"}})

(def app-routes
  (routes (api-routes roles scopes->roles) oauth2-routes))
```
# How it works?

Looking at example above it's clear that entire mechanism comes down to 3 elements:

* _roles_, for performance reasons unrolled by `init-roles` to contain no nested entries.
* _scopes->roles_ map which says how to translate an OAuth2 client's scope into a set of roles.
* a middleware which takes _roles_ and _scopes->roles_ and calculates roles/permissions.

One unknown is how middleware populates roles and permissions bearing in mind that two scenarios may happen:

1. Request is a user-originated, eg. user logged in and tries to view its own profile page.
   
   In this scenario, user initialized and stored in context by cerber's `wrap-authorized` middleware keeps its own roles and calculated permissions.

2. Request comes from an OAuth2 client.
   
   In this scenario OAuth2 client requests on behalf of user with approved set of scopes. Scopes are translated into roles (based on _scopes->roles_ mapping) and intersected with user's own roles.
   This is to avoid a situation where client's scopes may translate into roles exceeding user's own roles. Calculated permissions are also intersected with user's permissions to avoid potential elevation of priviledges.

# API

`(init-roles [roles-map])`

Initializes roles-to-permissions mapping.

Initialized mapping has no longer nested roles (they get unrolled with corresponding permissions).

`(has-role? [role principal])`

Returns true if `role` matches any of principal's set of `:roles` 

`(has-permission [permission principal])`

Returns true if `permission` matches any of principal's set of `:permissions`.
Permission can be exact, eg. `user:write` or wildcard one, like `user:*`.

``` clojure
(def user {:roles #{"user/read" "user/write"}
           :permissions #{(make-permission "project:read")
                          (make-permission "contacts:*")}}

(has-permission user "contacts:write"))
(has-role user "user/write")
```


