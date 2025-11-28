const fs = require("fs");

function getDockerRamLimit() {
    const paths = [
        "/sys/fs/cgroup/memory/memory.limit_in_bytes", // cgroup v1
        "/sys/fs/cgroup/memory.max"                    // cgroup v2
    ];

    for (const p of paths) {
        if (fs.existsSync(p)) {
            const raw = fs.readFileSync(p, "utf8").trim();

            // Unele sisteme pun "max" = fără limită
            if (raw === "max") return "No limit";

            const bytes = parseInt(raw);
            return (bytes / 1024 / 1024 / 1024).toFixed(2) + " GB";
        }
    }

    return "Cannot detect RAM limit";
}

console.log("Max RAM allowed:", getDockerRamLimit());


