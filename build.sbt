val catsVersion           = "2.3.0"
val catsEffectVersion     = "2.3.0"
val specs2Version         = "4.9.2"
val log4catsVersion       = "1.1.1"
val logbackVersion        = "1.2.3"
val scalacheckVersion     = "1.14.1"
val catsEffectTestVersion = "0.3.0"

lazy val root = (project in file("."))
  .settings(
    organization := "com.minosiants",
    name := "crypto",
    scalaVersion := "2.12.12",
    crossScalaVersions := Seq("2.12.12", "2.13.4"),
    scalacOptions ++= Seq("-Ywarn-unused", "-Yrangepos", "-Xlint"),
    javacOptions ++= Seq("-source", "1.15", "-target", "1.15"),
    libraryDependencies ++= Seq(
      "org.bouncycastle" % "bcprov-jdk15on" % "1.68",
      "org.typelevel"     %% "cats-core"                  % catsVersion,
      "org.typelevel"     %% "cats-effect"                % catsEffectVersion,
      "org.scalacheck"    %% "scalacheck"                 % scalacheckVersion % "test",
      "io.chrisdavenport" %% "log4cats-slf4j"             % log4catsVersion,
      "org.specs2"        %% "specs2-core"                % specs2Version % Test,
      "org.specs2"        %% "specs2-scalacheck"          % specs2Version % Test,
      "com.codecommit"    %% "cats-effect-testing-specs2" % catsEffectTestVersion % "test",
      "ch.qos.logback"    % "logback-classic"             % logbackVersion
    ),

    addCompilerPlugin(
      "org.typelevel" %% "kind-projector" % "0.11.1" cross CrossVersion.full
    ),
    addCompilerPlugin("com.olegpy"    %% "better-monadic-for" % "0.3.1"),
    publishTo := sonatypePublishToBundle.value

  ).settings(licenceSettings)
  .settings(releaseProcessSettings)

lazy val licenceSettings = Seq(
  organizationName := "Kaspar Minosiants",
  startYear := Some(2020),
  licenses += ("Apache-2.0", new URL(
    "https://www.apache.org/licenses/LICENSE-2.0.txt"
  ))
)

import ReleaseTransformations._
lazy val releaseProcessSettings = Seq(
  releaseIgnoreUntrackedFiles := true,
  releaseProcess := Seq[ReleaseStep](checkSnapshotDependencies,
    inquireVersions,
    runClean,
    runTest,
    setReleaseVersion,
    commitReleaseVersion,
    tagRelease,
    releaseStepCommandAndRemaining("+ publishSigned"),
    releaseStepCommand("sonatypeBundleRelease"),
    publishArtifacts,
    setNextVersion,
    commitNextVersion,
    pushChanges))



