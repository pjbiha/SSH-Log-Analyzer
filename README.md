# SSH Log Analyzer

A lightweight Python script that scans `auth.log` files and reports IP
addresses with repeated failed SSH login attempts.

## Features
* Pure standard-library Python (no external dependencies).
* Regex parsing of `Failed password … from <IP>` lines.
* Sliding-window counting (`--window`) and fail-threshold (`--fails`).
* CLI options for log path, window minutes, fail count, and year.

