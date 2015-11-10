name := "akka-http-spring-oauth2"

version := "0.0.1"

scalaVersion := "2.11.7"

libraryDependencies ++= {
  val akka_version = "2.4.0"
  val akka_http_version = "1.0"
  val spring_security_oauth2_version = "2.0.7.RELEASE"
  val servlet_api_version = "3.1.0"
  Seq(
    "com.typesafe.akka" %% "akka-http-experimental"               % akka_http_version,
    "com.typesafe.akka" %% "akka-http-spray-json-experimental"    % akka_http_version,
    "com.typesafe.akka" %% "akka-slf4j" % akka_version,
    "org.springframework.security.oauth" % "spring-security-oauth2" % spring_security_oauth2_version,
    "org.springframework.security" % "spring-security-jwt" % "1.0.3.RELEASE",
    "javax.servlet" % "javax.servlet-api" % servlet_api_version % "runtime",
    "ch.qos.logback" % "logback-classic" % "1.1.3" % "runtime",
	"org.slf4j" % "jcl-over-slf4j" % "1.7.12" % "runtime"	
  )
}

