import argparse
import asyncio
from dataclasses import dataclass, asdict
from datetime import date, timedelta
from typing import List

from playwright.async_api import Browser, Page, TimeoutError as PlaywrightTimeoutError, async_playwright


@dataclass
class Vulnerability:
    cve_id: str
    summary: str
    published: str
    last_modified: str
    cvss_score: str


def formatted_date(value: date) -> str:
    """Return a MM/DD/YYYY string as required by the NVD advanced search query parameters."""
    return value.strftime("%m/%d/%Y")


def build_search_url(week_start: date, week_end: date) -> str:
    """Assemble an advanced search URL that filters on publication dates."""
    start = formatted_date(week_start)
    end = formatted_date(week_end)
    return (
        "https://nvd.nist.gov/vuln/search/results"
        f"?form_type=Advanced&results_type=overview&search_type=all"
        f"&pub_date_start_date={start}&pub_date_end_date={end}"
    )


async def collect_rows(page: Page, verbose: bool = False) -> List[Vulnerability]:
    """Extract vulnerability data from the rendered search results table."""
    if verbose:
        print("Waiting for the results table...")
    await page.wait_for_selector("table tbody tr", timeout=60_000)
    rows = page.locator("table tbody tr")
    results: List[Vulnerability] = []
    for index in range(await rows.count()):
        row = rows.nth(index)
        cve_id = (await row.locator("th[scope='row'] a").inner_text()).strip()
        cells = row.locator("td")
        cell_count = await cells.count()
        summary = (await cells.nth(0).inner_text()).strip() if cell_count > 0 else ""
        published = (await cells.nth(1).inner_text()).strip() if cell_count > 1 else ""
        last_modified = (await cells.nth(2).inner_text()).strip() if cell_count > 2 else ""
        cvss_score = (await cells.nth(3).inner_text()).strip() if cell_count > 3 else ""
        results.append(
            Vulnerability(
                cve_id=cve_id,
                summary=summary,
                published=published,
                last_modified=last_modified,
                cvss_score=cvss_score,
            )
        )
    return results


async def dismiss_cookie_banner(page: Page) -> None:
    """Attempt to accept the OneTrust cookie banner if it appears."""
    try:
        await page.locator("#onetrust-accept-btn-handler").click(timeout=5_000)
    except PlaywrightTimeoutError:
        return


async def run_scrape(
    week_start: date,
    week_end: date,
    limit: int | None = None,
    debug_html: str | None = None,
    verbose: bool = False,
) -> List[Vulnerability]:
    """Execute the Playwright workflow end-to-end."""
    url = build_search_url(week_start, week_end)
    if verbose:
        print(f"Navigating to {url}")
    async with async_playwright() as playwright:
        browser: Browser = await playwright.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=60_000)
            await dismiss_cookie_banner(page)
            if verbose:
                print("Page loaded; collecting HTML snapshot" if debug_html else "Page loaded.")
            if debug_html:
                html = await page.content()
                with open(debug_html, "w", encoding="utf-8") as handle:
                    handle.write(html)
            await page.wait_for_timeout(5_000)
            vulnerabilities = await collect_rows(page, verbose=verbose)
        finally:
            await browser.close()

    if limit is not None:
        vulnerabilities = vulnerabilities[:limit]
    return vulnerabilities


def compute_week_range(reference: date | None = None) -> tuple[date, date]:
    """Return the current week's Monday-Sunday window for the provided date."""
    today = reference or date.today()
    start = today - timedelta(days=today.weekday())
    end = start + timedelta(days=6)
    # The search endpoint treats end dates in the future as today, so clamp.
    if end > today:
        end = today
    return start, end


def display(vulns: List[Vulnerability]) -> None:
    """Print results in a concise, human-friendly format."""
    if not vulns:
        print("No vulnerabilities published this week.")
        return

    for vuln in vulns:
        score = f" | Score: {vuln.cvss_score}" if vuln.cvss_score else ""
        print(f"{vuln.cve_id} | Published: {vuln.published}{score}")
        print(f"  {vuln.summary}")
        print(f"  Last Modified: {vuln.last_modified}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query nvd.nist.gov for vulnerabilities published during the current week."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of vulnerabilities to display (default shows all results).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--debug-html",
        type=str,
        default=None,
        help="Write the rendered HTML to the specified file before parsing.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress information during the scrape.",
    )
    args = parser.parse_args()

    week_start, week_end = compute_week_range()

    try:
        vulns = asyncio.run(
            run_scrape(week_start, week_end, args.limit, args.debug_html, args.verbose)
        )
    except PlaywrightTimeoutError:
        raise SystemExit("Timed out while waiting for NVD search results. Try again shortly.")

    if args.json:
        import json

        print(json.dumps([asdict(v) for v in vulns], indent=2))
    else:
        print(
            f"Vulnerabilities published between {formatted_date(week_start)} and {formatted_date(week_end)} "
            f"(total {len(vulns)}):\n"
        )
        display(vulns)


if __name__ == "__main__":
    main()
