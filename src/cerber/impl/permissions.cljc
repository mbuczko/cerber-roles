(ns cerber.impl.permissions
  (:require [clojure.set :as set]))

(defprotocol Wildcarded
  (wildcard-action? [this] "Returns true if action of permission is wildcarded")
  (wildcard-domain? [this] "Returns true if domain of permission is wildcarded")
  (matches? [this perm]    "Returns true if domain and actions match corresponding domain and actions of `perm`"))

(defrecord Permission [domain actions]
  Wildcarded
  (wildcard-action? [this]
    (= "*" actions))

  (wildcard-domain? [this]
    (= "*" domain))

  (matches? [this perm]
    (and (seq (:actions perm))
         (or (wildcard-domain? this)
             (= (:domain perm) domain))
         (or (wildcard-action? this)
             (every? actions (:actions perm))))))

(defn decompose-str
  [str]
  (when-let [arr (and (string? str)
                      (.split (.trim str) ":"))]
    (when (or (= -1 (.indexOf str ":"))
              (=  2 (count arr)))
      arr)))

(defn build
  [^String p]
  (let [[domain a-list] (decompose-str p)
        wildcard? (or (= p "*")
                      (= domain a-list "*"))]
    (when (or wildcard? (seq domain))
      (let [actions (when (and a-list (not= "*" a-list))
                      (into #{} (.split a-list ",")))]
        (->Permission (or domain "*")
                      (or actions "*"))))))

(defn intersect
  [src dest]
  (->> src
       (map #(some (fn [p]
                     (when (or (matches? % p)
                               (wildcard-domain? p)
                               (wildcard-domain? %)
                               (= (:domain %) (:domain p)))
                       (-> p
                           (cond-> (wildcard-domain? p)
                             (assoc :domain (:domain %)))
                           (cond-> (wildcard-action? p)
                             (assoc :actions (:actions %)))
                           (cond-> (and (not (wildcard-action? p))
                                        (not (wildcard-action? %)))
                             (assoc :actions (set/intersection
                                              (:actions %)
                                              (:actions p)))))))
                   dest))
       (filter #(seq (:actions %)))
       (set)))

(defn group-by-domain
  [m permissions]
  (loop [perms permissions, result m]
    (if-let [{:keys [domain actions] :as permission} (first perms)]
      (recur (rest perms)
             (update result domain #(if % (update % :actions into actions) permission)))
      result)))

(defn contains-matching-permission?
  [permissions ^Permission p]
  (some #(when (matches? % p) %) permissions))
