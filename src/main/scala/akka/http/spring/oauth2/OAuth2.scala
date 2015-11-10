package akka.http.spring.oauth2

import scala.annotation.implicitNotFound
import scala.collection.JavaConverters
import scala.collection.JavaConverters.asScalaSetConverter
import scala.collection.JavaConverters.mapAsScalaMapConverter
import scala.collection.mutable.HashMap
import scala.concurrent.Future
import scala.reflect.ClassTag
import scala.util.Failure
import scala.util.Success
import scala.util.Try
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.{ Authentication => SpringAuthentication }
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.oauth2.common.{ OAuth2AccessToken => SpringOAuth2AccessToken }
import org.springframework.security.oauth2.common.{ OAuth2RefreshToken => SpringOAuth2RefreshToken }
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import akka.http.scaladsl.marshalling.ToResponseMarshallable.apply
import akka.http.scaladsl.model.headers.BasicHttpCredentials
import akka.http.scaladsl.model.headers.HttpChallenge
import akka.http.scaladsl.model.headers.HttpCredentials
import akka.http.scaladsl.model.headers.OAuth2BearerToken
import akka.http.scaladsl.server.Directive.SingleValueModifiers
import akka.http.scaladsl.server.Directive.addByNameNullaryApply
import akka.http.scaladsl.server.Directive.addDirectiveApply
import akka.http.scaladsl.server.ExceptionHandler
import akka.http.scaladsl.server.Route
import akka.http.scaladsl.server.directives.AuthenticationDirective
import akka.http.scaladsl.server.directives.AuthenticationDirective.apply
import akka.http.scaladsl.server.directives.AuthenticationResult
import akka.http.scaladsl.server.directives.BasicDirectives.extractExecutionContext
import akka.http.scaladsl.server.directives.SecurityDirectives.authenticateOrRejectWithChallenge
import akka.http.scaladsl.server.directives.SecurityDirectives.challengeFor
import spray.json.DefaultJsonProtocol
import spray.json.JsNull
import spray.json.JsNumber
import spray.json.JsObject
import spray.json.JsString
import spray.json.JsValue
import spray.json.RootJsonFormat
import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.core.GrantedAuthority
import java.util.Collection
import java.util.HashSet
import java.util.ArrayList

case class OAuth2RefreshToken(value: String)

case class OAuth2AccessToken(
  value: String,
  tokenType: String,
  refreshToken: Option[OAuth2RefreshToken],
  expiresIn: Option[Int],
  scope: Option[Set[String]])

case class OAuth2Error(
  errorCode: Option[String],
  errorMessage: Option[String],
  additionalInformation: Option[Map[String, String]])

case class Authority(authority: String) {
  def getAuthority = authority
}

sealed trait Principal {
  def getName: String
}
case class User(username: String) extends Principal {
  override def getName = username
}
case class Client(clientId: String) extends Principal {
  override def getName = clientId
}

case class Authentication[T <: Principal](principal: T, authorities: Set[Authority])

object SpringSecurityImplicits {
  implicit def toOAuth2RefreshToken(token: SpringOAuth2RefreshToken) =
    if (token == null) null else OAuth2RefreshToken(token.getValue)

  implicit def toOAuth2AccessToken(token: SpringOAuth2AccessToken) =
    if (token == null) null else OAuth2AccessToken(
      token.getValue,
      token.getTokenType,
      Option(toOAuth2RefreshToken(token.getRefreshToken)),
      Option(token.getExpiresIn),
      Option(token.getScope).map { s => s.asScala.toSet })

  implicit def credentialToAuthentication(credential: HttpCredentials) = credential match {
    case BasicHttpCredentials(username, password) => new UsernamePasswordAuthenticationToken(username, password)
    case OAuth2BearerToken(token) => new PreAuthenticatedAuthenticationToken(token, "");
    case notSupported => throw new AuthenticationServiceException(s"authentication not supported : $notSupported")
  }

  import scala.collection.JavaConversions._
  implicit def toAuthentication(springAuth: SpringAuthentication): Authentication[_ <: Principal] = {
    val principal = springAuth match {
      case oauth2: OAuth2Authentication =>
        Option(oauth2.getUserAuthentication)
          .map(u => Client(u.getName))
          .getOrElse(Client(oauth2.getOAuth2Request().getClientId()))
      case _ => User(springAuth.getName())
    }
    import scala.collection.JavaConverters._
    val authorities = new ArrayList(springAuth.getAuthorities).toSet[GrantedAuthority].map { a => Authority(a.getAuthority) }
    Authentication(principal, authorities)
  }

}

trait OAuth2Protocols extends DefaultJsonProtocol with SprayJsonSupport {

  implicit object OAuth2AccessTokenFormat extends RootJsonFormat[OAuth2AccessToken] {
    def write(token: OAuth2AccessToken) = JsObject(
      SpringOAuth2AccessToken.ACCESS_TOKEN -> JsString(token.value),
      SpringOAuth2AccessToken.TOKEN_TYPE -> JsString(token.tokenType),
      SpringOAuth2AccessToken.REFRESH_TOKEN -> token.refreshToken.map { r => JsString(r.value) }.getOrElse(JsNull),
      SpringOAuth2AccessToken.EXPIRES_IN -> token.expiresIn.map { r => JsNumber(r) }.getOrElse(JsNull),
      SpringOAuth2AccessToken.SCOPE -> token.scope.map { s => JsString(s.mkString(",")) }.getOrElse(JsNull))

    def read(value: JsValue) = {
      null
    }
  }

  implicit object OAuth2ErrorFormat extends RootJsonFormat[OAuth2Error] {
    import collection.mutable.HashMap
    def write(error: OAuth2Error) = {
      val fields = new HashMap[String, JsValue]()
      error.errorCode.foreach { c => fields += ("error" -> JsString(c)) }
      error.errorMessage.foreach { d => fields += ("error_description" -> JsString(d)) }
      fields ++ error.additionalInformation.map(m => m.mapValues(JsString(_)))
      new JsObject(fields.toMap)
    }

    def read(value: JsValue) = {
      null
    }
  }
}

object Directives extends OAuth2Protocols {

  val oauth2ExceptionHandler = ExceptionHandler {
    case e: OAuth2Exception => ctx => {
      val err = OAuth2Error(
        Option(e.getOAuth2ErrorCode),
        Option(e.getMessage),
        Option(e.getAdditionalInformation).map { m => m.asScala.toMap })
      //TODO set status to 400
      ctx.complete(err)
    }
  }

  import SpringSecurityImplicits._
  def springAuth[C <: HttpCredentials: ClassTag, A](
    authManager: AuthenticationManager,
    mapAuth: SpringAuthentication => A): AuthenticationDirective[A] = {
    extractExecutionContext.flatMap { implicit ec ⇒
      authenticateOrRejectWithChallenge[C, A] { basic ⇒
        val authentication = basic.map(credential => (Try(authManager.authenticate(credential)), credential))
        Future.successful(authentication match {
          case Some((Success(auth), _)) => {
            AuthenticationResult.success(mapAuth(auth))
          }
          case Some((Failure(e), credential)) => AuthenticationResult.failWithChallenge(
            HttpChallenge(scheme = credential.scheme(), realm = "api", Map("error" -> e.getMessage)))
          case None => AuthenticationResult.failWithChallenge(challengeFor("api"))
        })
      }
    }
  }

  def springAuth[C <: HttpCredentials: ClassTag](
    authManager: AuthenticationManager) = springAuth[C, SpringAuthentication](authManager, identity)

  def springBasicAuth(authManager: AuthenticationManager) = springAuth[BasicHttpCredentials](authManager)
  def springOAuth2Auth(authManager: AuthenticationManager) = springAuth[OAuth2BearerToken](authManager)

  def authenticate[C <: HttpCredentials: ClassTag](
    authManager: AuthenticationManager) = springAuth[C, Authentication[_ <: Principal]](authManager, toAuthentication)

  def basic(authManager: AuthenticationManager) = authenticate[BasicHttpCredentials](authManager)
  def oauth2(authManager: OAuth2AuthenticationManager) = authenticate[OAuth2BearerToken](authManager)

}

object OAuth2 {
  import akka.http.scaladsl.server.Directives._
  import Directives._
  import SpringSecurityImplicits._
  import scala.collection.JavaConverters._

  def tokenRoute(authManager: AuthenticationManager, tokenEndPoint: TokenEndpoint): Route =
    pathPrefix("oauth") {
      handleExceptions(oauth2ExceptionHandler) {
        path("token") {
          springBasicAuth(authManager) { auth =>
            post { ctx =>
              ctx.complete {
                val parameters = ctx.request.uri.query.toMap.asJava
                val res = tokenEndPoint.postAccessToken(auth, parameters)
                toOAuth2AccessToken(res.getBody())
              }
            }
          }
        }
      }
    }
}