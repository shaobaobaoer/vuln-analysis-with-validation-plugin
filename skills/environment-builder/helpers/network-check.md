# Network Detection and Proxy Handling

Before cloning a project or performing any network operation, run the checks in this file first.

---

## Step 1: Detect Existing Proxy Configuration

```bash
check_proxy() {
    # Check environment variables
    if [ -n "$http_proxy" ] || [ -n "$https_proxy" ] || [ -n "$HTTP_PROXY" ] || [ -n "$HTTPS_PROXY" ]; then
        echo "Proxy configuration detected:"
        [ -n "$http_proxy" ]  && echo "  http_proxy=$http_proxy"
        [ -n "$https_proxy" ] && echo "  https_proxy=$https_proxy"
        [ -n "$HTTP_PROXY" ]  && echo "  HTTP_PROXY=$HTTP_PROXY"
        [ -n "$HTTPS_PROXY" ] && echo "  HTTPS_PROXY=$HTTPS_PROXY"
        return 0
    fi

    # Check git global proxy
    GIT_PROXY=$(git config --global http.proxy 2>/dev/null)
    if [ -n "$GIT_PROXY" ]; then
        echo "Git proxy detected: $GIT_PROXY"
        return 0
    fi

    echo "No proxy configuration detected"
    return 1
}
```

---

## Step 2: Network Connectivity Test

```bash
test_connectivity() {
    echo "Testing network connectivity..."

    # Test GitHub (most likely to timeout in China)
    GITHUB_OK=false
    if curl -s --connect-timeout 5 --max-time 10 -o /dev/null -w "%{http_code}" https://github.com 2>/dev/null | grep -qE "^(200|301|302)"; then
        GITHUB_OK=true
        echo "  GitHub is directly reachable"
    else
        echo "  GitHub connection timed out or unreachable"
    fi

    # Test domestic site (confirm it's not a complete network outage)
    DOMESTIC_OK=false
    if curl -s --connect-timeout 5 --max-time 10 -o /dev/null https://www.baidu.com 2>/dev/null; then
        DOMESTIC_OK=true
        echo "  Domestic network is working"
    else
        echo "  Domestic network is also down (possible complete network outage)"
    fi

    # Diagnosis conclusion
    if [ "$GITHUB_OK" = "true" ]; then
        echo "Conclusion: Network is normal, can clone directly"
        return 0
    elif [ "$DOMESTIC_OK" = "true" ]; then
        echo "Conclusion: Domestic network is normal but GitHub is unreachable, proxy or mirror needed"
        return 1
    else
        echo "Conclusion: Network is down, please check your network connection"
        return 2
    fi
}
```

---

## Step 3: Git Clone (With Timeout Detection and Auto-Fallback)

```bash
safe_git_clone() {
    local url="$1"
    local dest="$2"
    local timeout=${3:-120}  # Default 120 second timeout

    echo "Cloning: $url"

    # Attempt 1: Direct clone
    if timeout ${timeout} git clone --depth 1 "$url" "$dest" 2>&1; then
        echo "Clone successful"
        return 0
    fi

    echo "Direct clone failed, diagnosing network..."

    # Check if it's a network issue
    if ! curl -s --connect-timeout 5 -o /dev/null https://github.com 2>/dev/null; then
        echo "Confirmed network issue (GitHub unreachable)"

        # Attempt 2: GitHub mirror sites
        local repo_path
        repo_path=$(echo "$url" | sed -E 's|https?://github\.com/||; s|\.git$||')

        local mirrors=(
            "https://ghfast.top/https://github.com/${repo_path}.git"
            "https://github.moeyy.xyz/https://github.com/${repo_path}.git"
            "https://gitclone.com/github.com/${repo_path}.git"
        )

        for mirror_url in "${mirrors[@]}"; do
            echo "  Trying mirror: $mirror_url"
            rm -rf "$dest" 2>/dev/null
            if timeout ${timeout} git clone --depth 1 "$mirror_url" "$dest" 2>&1; then
                # Fix remote to point to original URL
                cd "$dest" && git remote set-url origin "$url" && cd -
                echo "Clone successful via mirror"
                return 0
            fi
        done

        # Attempt 3: Ask user to configure proxy
        echo ""
        echo "All mirrors failed. Please configure a proxy and retry:"
        echo ""
        echo "  Method A: Set environment variables"
        echo "    export https_proxy=http://127.0.0.1:<port>"
        echo "    export http_proxy=http://127.0.0.1:<port>"
        echo ""
        echo "  Method B: Set git proxy"
        echo "    git config --global http.proxy http://127.0.0.1:<port>"
        echo "    git config --global https.proxy http://127.0.0.1:<port>"
        echo ""
        echo "  Method C: If you have a socks5 proxy"
        echo "    git config --global http.proxy socks5://127.0.0.1:<port>"
        echo ""
        echo "  Let me know once configured, and I will re-clone."
        return 1
    else
        # GitHub is reachable but clone failed (possibly repo doesn't exist, permission issue, etc.)
        echo "GitHub is reachable but clone failed, possibly wrong repo URL or authentication required"
        return 1
    fi
}
```

---

## Usage

The agent calls these in order before cloning:

```bash
# 1. Check if there's an existing proxy
check_proxy

# 2. Test connectivity
test_connectivity
NETWORK_STATUS=$?

# 3. If GitHub is unreachable and no proxy, warn the user first
if [ "$NETWORK_STATUS" -eq 1 ]; then
    echo "GitHub is unreachable, will automatically try mirror sites during clone"
elif [ "$NETWORK_STATUS" -eq 2 ]; then
    echo "Network is completely down, please check your network connection first"
    exit 1
fi

# 4. Clone (internally handles timeout and mirror fallback)
safe_git_clone "https://github.com/user/repo.git" "${SETUP_ROOT}/repo"
```

---

## Verification After Proxy Setup

After the user configures a proxy, use the following commands to quickly verify:

```bash
curl -s --connect-timeout 5 -o /dev/null -w "GitHub: HTTP %{http_code} (%{time_total}s)\n" https://github.com
git ls-remote --exit-code https://github.com/torvalds/linux.git HEAD >/dev/null 2>&1 && echo "Git proxy is working" || echo "Git is still unreachable"
```
