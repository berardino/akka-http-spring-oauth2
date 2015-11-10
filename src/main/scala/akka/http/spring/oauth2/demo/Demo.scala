

package akka.http.spring.oauth2.demo

import akka.http.spring.oauth2.Directives._

import akka.http.spring.oauth2.OAuth2
import spray.json.DefaultJsonProtocol
import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import akka.http.scaladsl.server.directives.DebuggingDirectives
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import akka.http.scaladsl.server.Directives._
import com.typesafe.config.ConfigFactory
import akka.http.scaladsl.Http
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager

case class Account(username: String)

trait Protocols extends DefaultJsonProtocol with SprayJsonSupport {
  implicit val accountFormat = jsonFormat1(Account.apply)
}

object Demo extends App with Protocols with DebuggingDirectives {

  val context = new AnnotationConfigApplicationContext(Array(classOf[OAuth2ServerConfig]): _*)
  val tokenEndPoint = context.getBean(classOf[TokenEndpoint])
  implicit val clientAuthenticationManager = context.getBean("clientAuthenticationManager", classOf[AuthenticationManager])
  implicit val oauth2AuthenticationManager = context.getBean(classOf[OAuth2AuthenticationManager])

  implicit val system = ActorSystem("demo")
  implicit val materialized = ActorMaterializer()
  val config = ConfigFactory.load()

  val accountRountes = path("account") {
    get {
      oauth2(oauth2AuthenticationManager) { auth =>
        println(auth)
        complete { Account(auth.principal.getName) }
      }
    }
  }

  val oauth2Routes = OAuth2.tokenRoute(clientAuthenticationManager, tokenEndPoint)

  Http().bindAndHandle(accountRountes ~ oauth2Routes, config.getString("http.interface"), config.getInt("http.port"))
}