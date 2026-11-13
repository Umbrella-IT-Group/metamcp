/**
 * Copies text to the clipboard. Returns false when the browser refuses (no
 * permission, an insecure context), so the caller can say so instead of
 * showing a "copied" message that is not true.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error("Copy to clipboard failed:", error);
    return false;
  }
}
