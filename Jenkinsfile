#!groovy

// Keep the version in sync with the one used in pom.xml in order to get correct syntax completion.
@Library('github.com/cloudogu/ces-build-lib@59d3e94')
import com.cloudogu.ces.cesbuildlib.*

node('docker') {

  // Change this as when we go back to default - necessary for proper SonarQube analysis
  mainBranch = '2.0.0-m3'

  properties([
    // Keep only the last 10 build to preserve space
    buildDiscarder(logRotator(numToKeepStr: '10')),
    disableConcurrentBuilds(),
    parameters([
      string(name: 'dockerTag', trim: true, defaultValue: 'latest', description: 'Extra Docker Tag for cloudogu/scm-manager image')
    ])
  ])

  timeout(activity: true, time: 30, unit: 'MINUTES') {

    catchError {

      Maven mvn = setupMavenBuild()

      stage('Checkout') {
        checkout scm
      }

      stage('Build and test') {
        mvn 'clean install -Pdoc -pl :scm-git-plugin -am'
      }

      def commitHash = getCommitHash()
      def dockerImageTag = "2.0.0-dev-${commitHash.substring(0,7)}-${BUILD_NUMBER}"

    }

    // Archive Unit and integration test results, if any
    junit allowEmptyResults: true, testResults: '**/target/failsafe-reports/TEST-*.xml,**/target/surefire-reports/TEST-*.xml,**/target/jest-reports/TEST-*.xml'

    // Find maven warnings and visualize in job
    warnings consoleParsers: [[parserName: 'Maven']], canRunOnFailed: true

    mailIfStatusChanged(commitAuthorEmail)
  }
}

String mainBranch

Maven setupMavenBuild() {
  // Keep this version number in sync with .mvn/maven-wrapper.properties
  Maven mvn = new MavenInDocker(this, '3.5.2-jdk-8')

  if (isMainBranch()) {
    // Release starts javadoc, which takes very long, so do only for certain branches
    mvn.additionalArgs += ' -DperformRelease'
    // JDK8 is more strict, we should fix this before the next release. Right now, this is just not the focus, yet.
    mvn.additionalArgs += ' -Dmaven.javadoc.failOnError=false'
  }
  return mvn
}

void analyzeWith(Maven mvn) {

  withSonarQubeEnv('sonarcloud.io-scm') {

    String mvnArgs = "${env.SONAR_MAVEN_GOAL} " +
      "-Dsonar.host.url=${env.SONAR_HOST_URL} " +
      "-Dsonar.login=${env.SONAR_AUTH_TOKEN} "

    if (isPullRequest()) {
      echo "Analysing SQ in PR mode"
      mvnArgs += "-Dsonar.pullrequest.base=${env.CHANGE_TARGET} " +
        "-Dsonar.pullrequest.branch=${env.CHANGE_BRANCH} " +
        "-Dsonar.pullrequest.key=${env.CHANGE_ID} " +
        "-Dsonar.pullrequest.provider=bitbucketcloud " +
        "-Dsonar.pullrequest.bitbucketcloud.owner=sdorra " +
        "-Dsonar.pullrequest.bitbucketcloud.repository=scm-manager " +
        "-Dsonar.cpd.exclusions=**/*StoreFactory.java,**/*UserPassword.js "
    } else {
      mvnArgs += " -Dsonar.branch.name=${env.BRANCH_NAME} "
      if (!isMainBranch()) {
        // Avoid exception "The main branch must not have a target" on main branch
        mvnArgs += " -Dsonar.branch.target=${mainBranch} "
      }
    }
    mvn "${mvnArgs}"
  }
}

boolean isMainBranch() {
  return mainBranch.equals(env.BRANCH_NAME)
}

boolean waitForQualityGateWebhookToBeCalled() {
  boolean isQualityGateSucceeded = true
  timeout(time: 5, unit: 'MINUTES') { // Needed when there is no webhook for example
    def qGate = waitForQualityGate()
    echo "SonarQube Quality Gate status: ${qGate.status}"
    if (qGate.status != 'OK') {
      isQualityGateSucceeded = false
    }
  }
  return isQualityGateSucceeded
}

String getCommitAuthorComplete() {
  new Sh(this).returnStdOut 'hg log --branch . --limit 1 --template "{author}"'
}

String getCommitHash() {
  new Sh(this).returnStdOut 'hg log --branch . --limit 1 --template "{node}"'
}

String getCommitAuthorEmail() {
  def matcher = getCommitAuthorComplete() =~ "<(.*?)>"
  matcher ? matcher[0][1] : ""
}
