(set-env!
 :source-paths #{"src" "test"}
 :dependencies '[[org.clojure/clojure "1.8.0" :scope "provided"]
                 [adzerk/bootlaces "0.1.13" :scope "test"]
                 [metosin/boot-alt-test "0.3.2" :scope "test"]])

;; to check the newest versions:
;; boot -d boot-deps ancient

(def +version+ "0.1.0")

(require
 '[adzerk.bootlaces :refer :all]
 '[metosin.boot-alt-test :refer [alt-test]])

(bootlaces! +version+)

(task-options!
 pom {:project 'cerber/cerber-roles
      :version +version+
      :description "Roles and permissions made easy"
      :url "https://github.com/mbuczko/cerber-roles"
      :scm {:url "https://github.com/mbuczko/cerber-roles"}})
