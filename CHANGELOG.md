# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0-nx] - 2026-10-21
### Changed
- Ported to Python 3 and WebKit2GTK+ API 4.1/4.0 (WebTrap-nx)
- Cloner finds its templates next to the scripts, copies session.js to the output directory and rewrites page-relative links

### Fixed
- Trap server no longer fails to log POST requests whose data or headers contain "%"
- Trap server accepts a POST without Content-Length

## [1.0.1] - 2018-03-27
### Added
- Trap server now supports logging to a file
- This CHANGELOG file

### Changed
- TrapServer now doesn't requires to receive syslog server

## [1.0.0] - 2017-12-28
### Added
- Created the project, with web cloner and trap server modules.
