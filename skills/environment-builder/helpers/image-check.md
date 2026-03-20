# Docker Image Check and Pull

Use this function to ensure a Docker image is available whenever one is needed.

---

## ensure_image Function

Check locally first; if not available locally, pull from remote; if remote fails, try fallback mirrors:

```bash
ensure_image() {
    local image="$1"

    if docker image inspect "$image" > /dev/null 2>&1; then
        echo "Image already available locally: $image"
        return 0
    fi

    echo "Pulling: $image"
    if docker pull "$image" 2>/dev/null; then
        echo "Pull successful: $image"
        return 0
    fi

    echo "Default registry failed, trying fallback mirrors..."
    local short_name
    short_name=$(echo "$image" | sed 's|.*/||')

    local mirrors=(
        "registry.cn-hangzhou.aliyuncs.com/library/${short_name}"
        "docker.mirrors.ustc.edu.cn/library/${short_name}"
    )

    for mirror_image in "${mirrors[@]}"; do
        if docker pull "$mirror_image" 2>/dev/null; then
            docker tag "$mirror_image" "$image"
            echo "Successfully pulled via fallback mirror: $image"
            return 0
        fi
    done

    echo "Failed to obtain image: $image" >&2
    return 1
}
```

Only call this when the corresponding image is actually needed; do not pre-pull unnecessary images.
