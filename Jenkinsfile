#!groovy

// Keep the version in sync with the one used in pom.xml in order to get correct syntax completion.
@Library('github.com/cloudogu/ces-build-lib@1.35.1')
import com.cloudogu.ces.cesbuildlib.*

node('docker') {

  // Change this as when we go back to default - necessary for proper SonarQube analysis
  mainBranch = 'develop'

  properties([
    // Keep only the last 10 build to preserve space
    buildDiscarder(logRotator(numToKeepStr: '10')),
    disableConcurrentBuilds(),
    parameters([
      string(name: 'dockerTag', trim: true, defaultValue: 'latest', description: 'Extra Docker Tag for cloudogu/scm-manager image')
    ])
  ])

  timeout(activity: true, time: 40, unit: 'MINUTES') {

    Git git = new Git(this)

    catchError {

      Maven mvn = setupMavenBuild()

      stage('Checkout') {
        checkout scm
      }

      stage('Build') {
        mvn 'clean install -DskipTests'
      }

      stage('Unit Test') {
        mvn 'test -Pcoverage -Dmaven.test.failure.ignore=true'
      }

      stage('Integration Test') {
        mvn 'verify -Pit -pl :scm-webapp,:scm-it -Dmaven.test.failure.ignore=true -Dscm.git.core.trustfolderstat=false'
      }

      stage('SonarQube') {

        analyzeWith(mvn)

        if (!waitForQualityGateWebhookToBeCalled()) {
          currentBuild.result = 'UNSTABLE'
        }
      }

      def commitHash = git.getCommitHash()
      def dockerImageTag = "2.0.0-dev-${commitHash.substring(0,7)}-${BUILD_NUMBER}"

      if (isMainBranch()) {

        stage('Lifecycle') {
          try {
            // failBuildOnNetworkError -> so we can catch the exception and neither fail nor make our build unstable
            nexusPolicyEvaluation iqApplication: selectedApplication('scm'), iqScanPatterns: [[scanPattern: 'scm-server/target/scm-server-app.zip']], iqStage: 'build', failBuildOnNetworkError: true
          } catch (Exception e) {
            echo "ERROR: iQ Server policy eval failed. Not marking build unstable for now."
            echo "ERROR: iQ Server Exception: ${e.getMessage()}"
          }
        }

        stage('Archive') {
          archiveArtifacts 'scm-webapp/target/scm-webapp.war'
          archiveArtifacts 'scm-server/target/scm-server-app.*'
        }

        stage('Docker') {
          def image = docker.build('cloudogu/scm-manager')
          docker.withRegistry('', 'hub.docker.com-cesmarvin') {
            image.push(dockerImageTag)
            image.push('latest')
            if (!'latest'.equals(params.dockerTag)) {
              image.push(params.dockerTag)

              def newDockerTag = "2.0.0-${commitHash.substring(0,7)}-dev-${params.dockerTag}"
              currentBuild.description = newDockerTag
              image.push(newDockerTag)
            }
          }
        }

        stage('Deployment') {
          build job: 'scm-manager/next-scm.cloudogu.com', propagate: false, wait: false, parameters: [
            string(name: 'changeset', value: commitHash),
            string(name: 'imageTag', value: dockerImageTag)
          ]
        }
      }
    }

    // Archive Unit and integration test results, if any
    junit allowEmptyResults: true, testResults: '**/target/failsafe-reports/TEST-*.xml,**/target/surefire-reports/TEST-*.xml,**/target/jest-reports/TEST-*.xml'

    mailIfStatusChanged(git.commitAuthorEmail)
  }
}

String mainBranch

Maven setupMavenBuild() {
  Maven mvn = new MavenWrapperInDocker(this, "scmmanager/java-build:11.0.6_10")

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

