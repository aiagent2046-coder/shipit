import app.fixpack.semantic_check as semantic_check


def environment_from_argv(
    argv: list[str],
) -> dict[str, str]:
    environment: dict[str, str] = {}

    for index, token in enumerate(
        argv[:-1]
    ):
        if token != "-e":
            continue

        assignment = argv[index + 1]

        if "=" not in assignment:
            continue

        name, value = assignment.split(
            "=",
            1,
        )

        environment[name] = value

    return environment


def assert_writable_tool_home(
    argv: list[str],
) -> None:
    """Two homes, on purpose.

    This used to assert that all five paths sat under /tmp/shipit-home. That
    encoded the implementation rather than the requirement, and the
    implementation turned out to be wrong for two of them: /tmp is a tmpfs,
    and package caches grow without bound. What must hold is that nothing
    assumes an image-specific home, that the small state is disposable, and
    that the caches are somewhere with real disk behind them.
    """
    environment = environment_from_argv(
        argv
    )

    # Small, disposable tool state: the tmpfs is right for this.
    assert environment["HOME"] == (
        "/tmp/shipit-home"
    )

    assert environment[
        "XDG_CACHE_HOME"
    ] == "/tmp/shipit-home/.cache"

    assert environment[
        "XDG_CONFIG_HOME"
    ] == "/tmp/shipit-home/.config"

    # Package caches: the bind mount, because a tmpfs is RAM with a ceiling
    # and pnpm's store proved that ceiling is reachable on a real repository.
    assert environment[
        "npm_config_cache"
    ] == "/work/.shipit_npm_cache"

    assert environment[
        "PIP_CACHE_DIR"
    ] == "/work/.shipit_pip_cache"

    for name in (
        "npm_config_cache",
        "PIP_CACHE_DIR",
    ):
        assert not environment[name].startswith("/tmp"), (
            f"{name} is back on the tmpfs; a large install will fill it"
        )

    # The original requirement, unchanged: never an image-specific home.
    for name in (
        "HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "npm_config_cache",
        "PIP_CACHE_DIR",
    ):
        assert "/home/node" not in (
            environment[name]
        )


def test_install_container_uses_writable_tool_home():
    argv = semantic_check._docker_install_argv(
        "node:20-slim",
        "/tmp/customer-repository",
        "npm install",
    )

    assert_writable_tool_home(argv)


def test_offline_container_uses_same_writable_tool_home():
    argv = semantic_check._docker_test_argv(
        "node:20-slim",
        "/tmp/customer-repository",
        "npm run build",
    )

    assert_writable_tool_home(argv)

    network_index = argv.index(
        "--network"
    )

    assert argv[network_index + 1] == "none"


def test_both_containers_agree_on_every_cache_path():
    """The install container fills the caches and the offline one reads them.
    A path that differed between the two would silently re-download nothing --
    it would just find an empty cache and fail offline, with no network to
    fall back on."""
    install = environment_from_argv(
        semantic_check._docker_install_argv(
            "node:20-slim", "/tmp/repo", "npm install",
        )
    )
    offline = environment_from_argv(
        semantic_check._docker_test_argv(
            "node:20-slim", "/tmp/repo", "npm test",
        )
    )

    for name in (
        "HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "npm_config_cache",
        "PIP_CACHE_DIR",
    ):
        assert install[name] == offline[name], name
