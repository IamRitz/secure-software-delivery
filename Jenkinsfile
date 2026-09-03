pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
    }

    triggers {
        cron('H 6 * * 1')
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

        stage('Dependency scanning') {
            parallel {
                stage('npm audit') {
                    steps {
                        sh 'mkdir -p reports'
                        script {
                            docker.image('node:22.23.2-alpine3.24').inside {
                                sh '''
                                    set +e
                                    npm audit --json --package-lock-only > reports/npm-audit.json
                                    audit_status=$?
                                    set -e
                                    node security/scripts/validate-dependency-report.mjs npm-audit reports/npm-audit.json
                                    echo "npm audit exit code: $audit_status (security gate evaluates findings)"
                                '''
                            }
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'reports/npm-audit.json', allowEmptyArchive: false
                        }
                    }
                }

                stage('OSV-Scanner') {
                    steps {
                        sh 'mkdir -p reports'
                        script {
                            docker.image('ghcr.io/google/osv-scanner@sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475').inside('--entrypoint=') {
                                sh '''
                                    set +e
                                    /osv-scanner scan source --lockfile=package-lock.json --format=json > reports/osv-scanner.json
                                    osv_status=$?
                                    set -e
                                    echo "OSV-Scanner exit code: $osv_status (security gate evaluates findings)"
                                '''
                            }
                            docker.image('node:22.23.2-alpine3.24').inside {
                                sh 'node security/scripts/validate-dependency-report.mjs osv-scanner reports/osv-scanner.json'
                            }
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'reports/osv-scanner.json', allowEmptyArchive: false
                        }
                    }
                }
            }
        }

        stage('SAST') {
            steps {
                sh 'mkdir -p reports'
                script {
                    docker.image('semgrep/semgrep@sha256:12672acdb0949e19f9f6a4c2b288edd0b404f268f0ca7738a2c06f372f50362e').inside('--entrypoint=') {
                        sh '''
                            semgrep scan \
                                --config p/owasp-top-ten \
                                --config p/javascript \
                                --json-output=reports/semgrep.json \
                                --metrics=off \
                                --disable-version-check \
                                src
                        '''
                    }
                    docker.image('node:22.23.2-alpine3.24').inside {
                        sh 'node security/scripts/validate-semgrep-report.mjs reports/semgrep.json'
                    }
                    echo 'Semgrep report is ready for the security gate'
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/semgrep.json', allowEmptyArchive: false
                }
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    docker.image('node:22.23.2-alpine3.24').inside {
                        sh 'node security/scripts/security-gate.mjs'
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/security-gate.json,reports/gate-exceptions.json', allowEmptyArchive: false
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
