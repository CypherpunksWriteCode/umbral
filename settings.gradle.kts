pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "umbral"

include(":app")
include(":core:model")
include(":core:config")
include(":core:dns")
include(":core:net")
include(":core:i2p")
include(":core:tor")
include(":core:vpn")
