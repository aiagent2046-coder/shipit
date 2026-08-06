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
    environment = environment_from_argv(
        argv
    )

    assert environment["HOME"] == (
        "/tmp/shipit-home"
    )

    assert environment[
        "XDG_CACHE_HOME"
    ] == "/tmp/shipit-home/.cache"

    assert environment[
        "XDG_CONFIG_HOME"
    ] == "/tmp/shipit-home/.config"

    assert environment[
        "npm_config_cache"
    ] == "/tmp/shipit-home/.npm"

    assert environment[
        "PIP_CACHE_DIR"
    ] == "/tmp/shipit-home/.cache/pip"

    for name in (
        "HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "npm_config_cache",
        "PIP_CACHE_DIR",
    ):
        assert environment[name].startswith(
            "/tmp/shipit-home"
        )

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
