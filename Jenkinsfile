pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Secret scanning') {
            parallel {
                stage('Gitleaks') {
                    steps {
                        sh 'mkdir -p reports'
                        script {
                            docker.image('ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f').inside('--entrypoint=') {
                                sh 'gitleaks git . --platform github --no-banner --redact=100 --report-format json --report-path reports/gitleaks.json --exit-code 0'
                            }
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'reports/gitleaks.json', allowEmptyArchive: false
                        }
                    }
                }

                stage('TruffleHog') {
                    steps {
                        sh 'mkdir -p reports'
                        script {
                            docker.image('trufflesecurity/trufflehog@sha256:deb2af10659a488a14d262a323addcde099d99827a1cf1dc4e93c17915c39f08').inside('--entrypoint=') {
                                sh 'trufflehog git "file://$WORKSPACE" --json --no-update --results=verified,unverified,unknown --no-fail --fail-on-scan-errors > reports/trufflehog.raw.jsonl'
                            }
                            docker.image('node:22.23.2-alpine3.24').inside {
                                sh 'node security/scripts/normalize-trufflehog.mjs reports/trufflehog.raw.jsonl reports/trufflehog.json'
                            }
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'reports/trufflehog.json', allowEmptyArchive: false
                        }
                    }
                }
            }
        }

        stage('Install') {
            agent {
                docker {
                    image 'node:22.23.2-alpine3.24'
                    reuseNode true
                }
            }
            steps {
                sh 'npm ci'
            }
        }

        stage('Lint') {
            agent {
                docker {
                    image 'node:22.23.2-alpine3.24'
                    reuseNode true
                }
            }
            steps {
                sh 'npm run lint'
            }
        }

        stage('Test') {
            agent {
                docker {
                    image 'node:22.23.2-alpine3.24'
                    reuseNode true
                }
            }
            steps {
                sh 'npm test'
            }
        }
    }
}
