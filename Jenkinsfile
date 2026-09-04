pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
    }

    parameters {
        booleanParam(
            name: 'ENABLE_AWS_DELIVERY',
            defaultValue: false,
            description: 'Enable only after the documented AWS resources and Jenkins credentials exist'
        )
        string(name: 'AWS_REGION', defaultValue: 'us-east-1', description: 'AWS region')
        string(name: 'AWS_ACCOUNT_ID', defaultValue: '', description: 'Twelve-digit AWS account ID')
        string(name: 'ECR_REPOSITORY', defaultValue: 'secure-software-delivery', description: 'ECR repository name')
        string(name: 'ECS_CLUSTER', defaultValue: '', description: 'ECS cluster name')
        string(name: 'ECS_SERVICE', defaultValue: '', description: 'ECS service whose task uses the :demo tag')
    }

    triggers {
        cron('H 6 * * 1')
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_COMMIT = sh(
                        script: 'git rev-parse HEAD',
                        returnStdout: true
                    ).trim()
                    echo "Checked out commit ${env.GIT_COMMIT}"
                }
            }
        }

        stage('Secret scanning') {
            parallel {
                stage('Gitleaks') {
                    steps {
                        sh 'mkdir -p reports'
                        script {
                            docker.image('ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f').inside('--entrypoint=') {
                                sh 'gitleaks git . --config .gitleaks.toml --log-opts=HEAD --platform github --no-banner --redact=100 --report-format json --report-path reports/gitleaks.json --exit-code 0'
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
                                sh 'trufflehog git "file://$WORKSPACE" --json --no-update --exclude-paths=.trufflehog-exclude-paths.txt --results=verified,unverified,unknown --no-fail --fail-on-scan-errors > reports/trufflehog.raw.jsonl'
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
                                --config security/semgrep-rules.yml \
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

        stage('Docker Build') {
            when {
                allOf {
                    branch 'main'
                    not { triggeredBy 'TimerTrigger' }
                }
            }
            steps {
                echo 'Building application image without AWS or deployment credentials'
                sh 'docker build --tag "secure-software-delivery:$GIT_COMMIT" .'
            }
        }

        stage('AWS Configuration') {
            when {
                allOf {
                    branch 'main'
                    not { triggeredBy 'TimerTrigger' }
                }
            }
            steps {
                script {
                    if (params.ENABLE_AWS_DELIVERY) {
                        def missing = ['AWS_ACCOUNT_ID', 'AWS_REGION', 'ECR_REPOSITORY', 'ECS_CLUSTER', 'ECS_SERVICE']
                            .findAll { !params[it]?.trim() }
                        if (missing) {
                            error("AWS delivery was enabled but configuration is missing: ${missing.join(', ')}")
                        }
                        echo 'AWS delivery enabled; real ECR, scan, gate, and ECS stages will run'
                    } else {
                        echo 'AWS not configured — ECR push, image scan, deploy gate, and deploy skipped; see docs/aws-setup.md'
                    }
                }
            }
        }

        stage('ECR Push') {
            when {
                allOf {
                    branch 'main'
                    not { triggeredBy 'TimerTrigger' }
                    expression { params.ENABLE_AWS_DELIVERY }
                }
            }
            steps {
                script {
                    def registry = "${params.AWS_ACCOUNT_ID}.dkr.ecr.${params.AWS_REGION}.amazonaws.com"
                    withCredentials([
                        usernamePassword(
                            credentialsId: 'jenkins-aws-ecr',
                            usernameVariable: 'AWS_ACCESS_KEY_ID',
                            passwordVariable: 'AWS_SECRET_ACCESS_KEY'
                        )
                    ]) {
                        withEnv([
                            "AWS_DEFAULT_REGION=${params.AWS_REGION}",
                            "ECR_REGISTRY=${registry}",
                            "ECR_REPOSITORY=${params.ECR_REPOSITORY}"
                        ]) {
                            sh '''
                                set +x
                                docker run --rm \
                                    -e AWS_ACCESS_KEY_ID \
                                    -e AWS_SECRET_ACCESS_KEY \
                                    -e AWS_DEFAULT_REGION \
                                    amazon/aws-cli@sha256:269b824fd142de9de0bd6fa2e78cdcf3012c1b05f1792a8e44b30ad80680c83d \
                                    ecr get-login-password \
                                    | docker login --username AWS --password-stdin "$ECR_REGISTRY"
                                docker tag "secure-software-delivery:$GIT_COMMIT" "$ECR_REGISTRY/$ECR_REPOSITORY:$GIT_COMMIT"
                                docker tag "secure-software-delivery:$GIT_COMMIT" "$ECR_REGISTRY/$ECR_REPOSITORY:demo"
                                docker push "$ECR_REGISTRY/$ECR_REPOSITORY:$GIT_COMMIT"
                                docker push "$ECR_REGISTRY/$ECR_REPOSITORY:demo"
                            '''
                        }
                    }
                }
            }
            post {
                always {
                    script {
                        if (params.ENABLE_AWS_DELIVERY && params.AWS_ACCOUNT_ID?.trim()) {
                            sh "docker logout ${params.AWS_ACCOUNT_ID}.dkr.ecr.${params.AWS_REGION}.amazonaws.com || true"
                        }
                    }
                }
            }
        }

        stage('Image Scan') {
            when {
                allOf {
                    branch 'main'
                    not { triggeredBy 'TimerTrigger' }
                    expression { params.ENABLE_AWS_DELIVERY }
                }
            }
            steps {
                sh 'rm -f reports/ecr-image-scan.json reports/image-gate.json'
                script {
                    def dockerSocketGroup = sh(
                        script: "stat -c '%g' /var/run/docker.sock",
                        returnStdout: true
                    ).trim()
                    withCredentials([
                        usernamePassword(
                            credentialsId: 'jenkins-aws-ecr',
                            usernameVariable: 'AWS_ACCESS_KEY_ID',
                            passwordVariable: 'AWS_SECRET_ACCESS_KEY'
                        )
                    ]) {
                        withEnv([
                            "AWS_REGION=${params.AWS_REGION}",
                            "AWS_DEFAULT_REGION=${params.AWS_REGION}",
                            "ECR_REPOSITORY=${params.ECR_REPOSITORY}"
                        ]) {
                            docker.image('node@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5').inside(
                                "--group-add ${dockerSocketGroup} " +
                                '-v /var/run/docker.sock:/var/run/docker.sock ' +
                                '-v /usr/bin/docker:/usr/bin/docker:ro'
                            ) {
                                sh '''
                                    set +e
                                    node security/scripts/poll-ecr-scan.mjs \
                                        --repository "$ECR_REPOSITORY" \
                                        --image-tag "$GIT_COMMIT" \
                                        --region "$AWS_REGION" \
                                        --aws-cli-container amazon/aws-cli@sha256:269b824fd142de9de0bd6fa2e78cdcf3012c1b05f1792a8e44b30ad80680c83d \
                                        --output reports/ecr-image-scan.json
                                    scan_status=$?
                                    set -e
                                    echo "ECR scan polling exit code: $scan_status (deploy gate evaluates the report)"
                                '''
                            }
                        }
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/ecr-image-scan.json', allowEmptyArchive: true
                }
            }
        }

        stage('Deploy Gate') {
            when {
                allOf {
                    branch 'main'
                    not { triggeredBy 'TimerTrigger' }
                    expression { params.ENABLE_AWS_DELIVERY }
                }
            }
            steps {
                script {
                    docker.image('node:22.23.2-alpine3.24').inside {
                        sh 'node security/scripts/image-gate.mjs'
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/image-gate.json', allowEmptyArchive: false
                }
            }
        }

        stage('Deploy') {
            when {
                allOf {
                    branch 'main'
                    not { triggeredBy 'TimerTrigger' }
                    expression { params.ENABLE_AWS_DELIVERY }
                }
            }
            steps {
                script {
                    withCredentials([
                        usernamePassword(
                            credentialsId: 'jenkins-aws-deploy',
                            usernameVariable: 'AWS_ACCESS_KEY_ID',
                            passwordVariable: 'AWS_SECRET_ACCESS_KEY'
                        )
                    ]) {
                        sh """
                            docker run --rm \\
                                -e AWS_ACCESS_KEY_ID \\
                                -e AWS_SECRET_ACCESS_KEY \\
                                amazon/aws-cli@sha256:269b824fd142de9de0bd6fa2e78cdcf3012c1b05f1792a8e44b30ad80680c83d \\
                                ecs update-service \\
                                --cluster '${params.ECS_CLUSTER}' \\
                                --service '${params.ECS_SERVICE}' \\
                                --force-new-deployment \\
                                --region '${params.AWS_REGION}'
                        """
                    }
                }
            }
        }

    }
}
