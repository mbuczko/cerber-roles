(set-env!
 :source-paths #{"src" "test"}
 :dependencies '[[weavejester/dependency "0.2.1"]
                 [adzerk/bootlaces "0.1.13" :scope "test"]
                 [metosin/bat-test "0.4.0" :scope "test"]])

;; to check the newest versions:
;; boot -d boot-deps ancient

(def +version+ "1.0.0")

(require
 '[adzerk.bootlaces :refer :all]
 '[metosin.bat-test :refer [bat-test]])

(bootlaces! +version+)

(task-options!
 pom {:project 'cerber/cerber-roles
      :version +version+
      :description "Roles and permissions for Cerber."
      :url "https://github.com/mbuczko/cerber-roles"
      :scm {:url "https://github.com/mbuczko/cerber-roles"}})
