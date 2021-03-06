[![Clojars Project](https://img.shields.io/clojars/v/cerber/cerber-roles.svg)](https://clojars.org/cerber/cerber-roles)

# Roles and permissions

This simple library tries to fill in the gap between OAuth2 authorization and role-based access control.

Code has been separated from [Cerber OAuth2 Provider](https://github.com/mbuczko/cerber-oauth2-provider) implementation and published as optional add-on which hopefully makes scopes and roles easier to match.

## Terminology

Terminology used in this doc bases on Apache Shiro: http://shiro.apache.org/terminology.html

## Anatomy of Permission

Permission implemented by this library consists of two parts: a _domain_ and list of comma-separated _actions_, both joined with colon, like `user:read` or `user:read,write`.

This imposes 3 additional cases:

 - wildcard action: any action on given domain is allowed, eg: `user:*`, or simply `user`
 - wildcard domain: given action on any domain is allowed, eg: `*:write`
 - wildcard permission: any action on any domain is allowed: `*:*`, or simply `*`

## Anatomy of Role

Role is a collection of permissions. Technically, it is represented by a qualified keyword, eg. `:user/default` or `:admin/all`:

``` clojure
{:user/all      #{"user:read" "user:write"}
 :project/read  #{"project:read"}}
```

Roles may also map to wildcard actions and other roles (explicit- or wildcarded ones).

``` clojure
{:admin/all     "*"                          ;; maps to wildcard permission
 :admin/company #{:user/* :project/*}        ;; maps to other roles from user and project domains
 :project/all   #{"project:*" "timeline:*"}} ;; maps to wildcard-action permissions

```

# Usage

Once permissions and roles are defined and bound together with carefully crafted mapping, how to make them showing up in a request? 

A `wrap-permissions` middleware is an answer. It bases on a context set up by companion middleware - `wrap-authorized` exposed by [Cerber API](https://github.com/mbuczko/cerber-oauth2-provider) and populates subject's roles and permissions.

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

Now, the crucial step is to apply both `wrap-authorized` and `wrap-permissions` middlewares:

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
              :user/admin #{"photos:*" "comments:*"}
              
              ;; registered user can read and write to photos and comments
              :user/all #{"photos:read" "photos:write" "comments:read" "comments:write"}
              
              ;; unregistered user can only read photos and comments
              :user/unregistered #{"photos:read" "comments:read"}}))

(def scopes->roles {"resources:read"   #{:user/unregistered}
                    "resources:write"  #{:users/all}
                    "resources:manage" #{:user/admin}})

(def app-routes
  (routes (api-routes roles scopes->roles) oauth2-routes))
```
# How it works?

Looking at example above it's clear that entire mechanism boils down to 3 elements:

* _roles_, for performance reasons unrolled by `init-roles` to contain no nested entries.
* _scopes->roles_ map which says how to translate an OAuth2 client's scope into a set of roles.
* a middleware which takes _roles_ and _scopes->roles_ and calculates corresponding roles/permissions.

One unknown is how middleware populates roles and permissions bearing in mind that two scenarios may happen:

1. Request is a cookie-based user-originated one.
   
   In this scenario, subject initialized and stored in context by cerber's `wrap-authorized` middleware keeps its own roles and permissions calculated upon the roles.

2. Request is a token-based client-originated one.
   
   In this scenario OAuth2 client requests on behalf of user with approved set of scopes. Scopes are translated into roles (based on _scopes->roles_ mapping) and intersected with user's own roles.
   This is to avoid a situation where client's scopes may translate into roles exceeding user's own roles. Calculated permissions are also intersected with user's permissions to avoid potential elevation of priviledges.

# API

`(init-roles [roles-map])`

Initializes roles-to-permissions mapping.

Initialized mapping has no longer nested roles (they get unrolled with corresponding permissions).

`(make-permission str)`

Builds a `Permission` based on string consisting of domain and actions, separated by colon, like "user:read,write".
Permission may be exact one, have actions or domain (or both) wildcarded.

Wildcard is denoted by "\*", and means _any_, so "document:*" permission can be read as _any action on document_.

`(implied-by? [permission permissions])`

Returns resource `permission` if it's implied (has access to) by the set of `permissions`.
Returns falsey otherwise.

`(has-role? [subject role])`

Returns matching `role` if it's been found in `subject's` set of `:roles`.
Returns falsey otherwise.

`(has-permission [subject permission])`

Returns resource permission if it's implied by `subject`'s set of `:permissions`.
Returns falsey otherwise.

`(intersect-permissions [coll1 coll2])`

Intersects 2 sets of permissions calculating their common domains and actions.
For example, intersection of following permissions: `["*:read,write"]` and `["doc:read,create"]` results in `["doc:read"]`.

`(roles->permissions [roles mapping])`

Returns set of permissions based on collection of `roles` and `mapping` returned by `init-roles` function.

# Example

``` clojure
(def subject {:roles #{:user/read :user/write}
              :permissions #{(make-permission "project:read")
                             (make-permission "contacts:*")}}

(has-permission subject "contacts:write"))
(has-permission subject "contacts:read,write"))

(has-role? subject :user/write)

(implied-by? "document:read" 
             (intersect-permissions [(make-permission "document:read,write")
                                     (make-permission "workspace:create")
                                     (make-permission "document:delete,create")]
                                    [(make-permission "document:read,write")]))
```

# Set up for local development

This library uses clojure [deps](https://clojure.org/guides/deps_and_cli) and [revolt](https://github.com/mbuczko/revolt) to set up comfortable local environment:

```clojure
    clj -A:dev -p nrepl,watch,rebel
```

...and connect to the REPL.

# License

Eclipse Public License - v 2.0
