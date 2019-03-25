(ns cerber.impl.permissions
  (:require [clojure.set :as set]))

(defrecord Permission [domain actions])

(defn decompose-str
  [str]
  (when-let [arr (and (string? str)
                      (.split (.trim str) ":"))]
    (when (or (= -1 (.indexOf str ":"))
              (=  2 (count arr)))
      arr)))

(defn make-permission
  "Builds a `Permission` based on colon-separated string, like \"user:write\".

  Permission may be exact one, may have wildcard-action or have both domain
  and actions wildcarded. In this case a `:wildcard?` is set to true and both
  fields contain a wildcard symbol \"*\" as a value."

  [^String p]
  (let [[domain a-list] (decompose-str p)
        wildcard? (or (= p "*")
                      (= domain a-list "*"))]
    (when (or wildcard? (seq domain))
      (let [actions (when (and a-list (not= "*" a-list))
                      (into #{} (.split a-list ",")))]
        (->Permission (or domain "*")
                      (or actions "*"))))))

(defn contains-action?
  [actions ^String a]
  (or (= "*" actions)
      (contains? actions a)
      (seq (set/intersection actions a))))

(defn contains-exact-permission?
  [permissions ^Permission p]
  (contains? permissions p))

(defn contains-domain-action?
  [permissions {:keys [domain actions]}]
  (some #(and (or (= "*" (:domain %1))
                  (= domain (:domain %1)))
              (contains-action? (:actions %1) actions))
        permissions))

(defn contains-wildcard-permission?
  [permissions]
  (some :wildcard? permissions))

(defn contains-matching-permission?
  [permissions ^Permission p]
  (or (contains-exact-permission? permissions p)
      (contains-domain-action? permissions p)))
