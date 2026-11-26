let profilePromise;

export function fetchUserProfile() {
  return (profilePromise ??= fetch(
    document.querySelector('meta[name="user-profile-url"]')?.content,
    { signal: AbortSignal.timeout(3000) },
  )
    .then((response) => (response.status === 200 ? response.json() : null))
    .catch(() => null));
}
