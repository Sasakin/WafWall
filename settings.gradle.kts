pluginManagement {
    repositories {
        gradlePluginPortal()
    }
}

rootProject.name = "wave-wall"

include("common")
include("gateway")
include("processor")
include("alert")