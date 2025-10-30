import asyncio
from playwright.async_api import async_playwright
from datetime import date, timedelta


async def main():
    week_end = date.today()
    week_start = week_end - timedelta(days=6)
    start_str = week_start.strftime("%m/%d/%Y")
    end_str = week_end.strftime("%m/%d/%Y")
    url = (
        "https://nvd.nist.gov/vuln/search/results"
        f"?form_type=Advanced&results_type=overview&search_type=all"
        f"&pub_date_start_date={start_str}&pub_date_end_date={end_str}"
    )
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(url, wait_until="domcontentloaded")
        await page.wait_for_load_state("networkidle", timeout=60000)
        await page.wait_for_selector("table tbody tr", timeout=60000)
        print("Title:", await page.title())
        count = await page.locator("table tbody tr").count()
        print("Row count", count)
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
