import org.zaproxy.gradle.addon.AddOnStatus

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.13.1"
    id("com.diffplug.spotless")
    id("org.zaproxy.common")
}

description = "Adds the OWASP PTK extension to browsers launched from ZAP."

zapAddOn {
    addOnId.set("ptk")
    addOnName.set("OWASP PTK")
    zapVersion.set("2.17.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/owasp-ptk/")

        helpSet {
            baseName.set("org.zaproxy.addon.ptk.resources.help%LC%.helpset")
            localeToken.set("%LC%")
        }

        dependencies {
            addOns {
                register("selenium")
            }
        }
    }
}

java {
    val javaVersion = JavaVersion.VERSION_17
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

spotless {
    kotlinGradle {
        ktlint()
    }
}
