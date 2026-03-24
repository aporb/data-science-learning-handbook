"""
Chapter 03: Data Acquisition - Government Data Sources
=========================================================
Working with messy government file formats:
  - Legacy pipe-delimited and fixed-width files
  - FOIA PDF extraction (machine-generated and scanned)
  - Access database exports (.mdb/.accdb)
  - Multi-header Excel files from DoD financial systems

Requirements:
    pip install pandas pdfplumber openpyxl python-docx
    pip install pytesseract pillow  # For OCR on scanned PDFs
    # pytesseract also requires: sudo apt install tesseract-ocr  (Ubuntu)
    # or: brew install tesseract  (macOS)
"""

import io
import os
import struct
import zipfile
from pathlib import Path
from typing import Optional

import pandas as pd


# ---------------------------------------------------------------------------
# 1. Legacy CSV / pipe-delimited files
# ---------------------------------------------------------------------------

def read_dod_financial_csv(filepath: str) -> pd.DataFrame:
    """
    Defensive reader for DoD financial system CSV exports.
    Handles pipe delimiters, latin-1 encoding, multi-row headers,
    and the full zoo of null representations common in legacy systems.

    Many DFAS, GFEBS, and Navy ERP system exports use these patterns.
    Always read as string first, then cast — silent type coercion errors
    in financial data are catastrophically hard to find later.

    Args:
        filepath: Path to the CSV file

    Returns:
        Raw DataFrame with string types; caller handles casting
    """
    # Collect null representations seen in DoD financial system exports
    na_values = [
        "NULL", "null", "N/A", "n/a", "#N/A", "NA", "None", "none",
        "NONE", "-", "--", "---", ".", " ", "(blank)", "BLANK", "",
    ]

    # Try pipe-delimited first; fall back to comma if that produces one column
    for sep in ["|", ",", "\t", "~"]:
        try:
            df = pd.read_csv(
                filepath,
                sep=sep,
                encoding="latin-1",
                na_values=na_values,
                keep_default_na=True,
                dtype=str,           # Everything as string; cast explicitly after inspect
                low_memory=False,
                on_bad_lines="warn", # Don't crash on malformed rows — log them
            )
            # If we got more than one column, assume this is the right delimiter
            if df.shape[1] > 1:
                print(f"  Read {filepath}: {df.shape[0]:,} rows × {df.shape[1]} cols "
                      f"(delimiter='{sep}', encoding=latin-1)")
                return df
        except Exception as e:
            print(f"  Delimiter '{sep}' failed: {e}")
            continue

    raise ValueError(f"Could not read {filepath} with any delimiter")


def read_dod_financial_csv_with_multi_header(
    filepath: str,
    header_rows: int = 2,
    real_header_row: int = 1,
) -> pd.DataFrame:
    """
    Handle DoD financial exports with multi-row headers.
    These appear in GFEBS, DEAMS, and some SABRS exports where row 0
    is a report title and row 1 is the actual column header.

    Args:
        filepath: Path to the file
        header_rows: Number of header rows to skip past the title row
        real_header_row: Which of the header rows contains column names (0-indexed)

    Returns:
        DataFrame with correct column names
    """
    na_values = ["NULL", "N/A", "#N/A", "None", "-", "", " "]

    # Read the actual column names from the header row
    header_df = pd.read_csv(
        filepath,
        sep="|",
        encoding="latin-1",
        nrows=header_rows,
        dtype=str,
        header=None,
    )
    column_names = header_df.iloc[real_header_row].tolist()

    # Now read the data, skipping all header rows
    df = pd.read_csv(
        filepath,
        sep="|",
        encoding="latin-1",
        skiprows=header_rows + 1,  # Skip header rows + the blank row after headers
        header=None,
        names=column_names,
        na_values=na_values,
        dtype=str,
        low_memory=False,
    )

    return df


def read_fixed_width_export(
    filepath: str,
    colspecs: list[tuple[int, int]],
    col_names: list[str],
    encoding: str = "latin-1",
    skiprows: int = 0,
) -> pd.DataFrame:
    """
    Read a fixed-width positional file using a data dictionary.
    Common in DCPS (payroll), legacy Navy supply chain, and MILPAY exports.

    colspecs: list of (start, end) character positions (0-indexed, exclusive end)
    col_names: column names corresponding to each colspec

    Example data dictionary (from a fictional payroll extract):
        Cols 01-09:  Employee ID
        Cols 10-39:  Last Name (left-justified, space-padded)
        Cols 40-69:  First Name
        Cols 70-77:  Pay Period End Date (YYYYMMDD)
        Cols 78-87:  Gross Pay Amount (right-justified, 2 implied decimal places)

    Usage:
        df = read_fixed_width_export(
            "payroll_extract.dat",
            colspecs=[(0, 9), (9, 39), (39, 69), (69, 77), (77, 87)],
            col_names=["employee_id", "last_name", "first_name",
                       "pay_period_end", "gross_pay_str"]
        )
    """
    df = pd.read_fwf(
        filepath,
        colspecs=colspecs,
        names=col_names,
        encoding=encoding,
        skiprows=skiprows,
        dtype=str,          # Preserve leading zeros in ID fields
    )

    # Strip trailing whitespace common in space-padded fixed-width fields
    str_cols = df.select_dtypes(include="object").columns
    df[str_cols] = df[str_cols].apply(lambda col: col.str.strip())

    return df


# ---------------------------------------------------------------------------
# 2. FOIA PDF extraction
# ---------------------------------------------------------------------------

def extract_tables_from_pdf(
    pdf_path: str,
    pages: Optional[list[int]] = None,
) -> list[pd.DataFrame]:
    """
    Extract tables from a machine-generated (not scanned) PDF.
    pdfplumber handles most PDFs produced by printing from Excel, Word,
    or standard government report generators.

    Best results on:
    - FPDS Award Details PDFs
    - Contract award notices
    - Program office reports exported to PDF from Excel/SSRS

    Weak results on:
    - Scanned documents (use extract_tables_ocr instead)
    - PDFs with complex merged-cell tables

    Args:
        pdf_path: Path to the PDF file
        pages: List of page numbers (1-indexed) to extract from.
               None extracts all pages.

    Returns:
        List of DataFrames, one per extracted table

    Requires: pip install pdfplumber
    """
    try:
        import pdfplumber
    except ImportError:
        raise ImportError("pip install pdfplumber")

    tables = []

    with pdfplumber.open(pdf_path) as pdf:
        target_pages = pages if pages else range(1, len(pdf.pages) + 1)

        for page_num in target_pages:
            page = pdf.pages[page_num - 1]  # pdfplumber is 0-indexed
            extracted = page.extract_tables()

            for table in extracted:
                if not table or len(table) < 2:
                    continue

                # First row of the extracted table is typically the header
                headers = table[0]
                rows = table[1:]

                # Handle None values in headers (merged cells)
                headers = [
                    f"col_{i}" if h is None else str(h).strip()
                    for i, h in enumerate(headers)
                ]

                df = pd.DataFrame(rows, columns=headers)

                # Drop rows that are entirely empty
                df = df.dropna(how="all")

                # Strip whitespace from all string columns
                str_cols = df.select_dtypes(include="object").columns
                df[str_cols] = df[str_cols].apply(
                    lambda col: col.str.strip() if col.dtype == "object" else col
                )

                tables.append(df)
                print(f"  Page {page_num}: extracted table with "
                      f"{df.shape[0]} rows × {df.shape[1]} cols")

    return tables


def extract_text_from_scanned_pdf(
    pdf_path: str,
    dpi: int = 300,
    lang: str = "eng",
) -> list[str]:
    """
    Extract text from a scanned PDF using OCR (Tesseract).
    Use this when pdfplumber returns empty or near-empty text.

    Government FOIA responses frequently include scanned documents.
    Typical accuracy: 90-96% for clean prints, lower for handwritten
    annotations, coffee stains, or small font sizes.

    Args:
        pdf_path: Path to the PDF file
        dpi: Render resolution (higher = better OCR but slower)
        lang: Tesseract language code ("eng" for English)

    Returns:
        List of strings, one per page

    Requires:
        pip install pytesseract pillow pdf2image
        brew install tesseract poppler  (macOS)
        apt install tesseract-ocr poppler-utils  (Ubuntu)
    """
    try:
        import pytesseract
        from pdf2image import convert_from_path
    except ImportError:
        raise ImportError("pip install pytesseract pdf2image; also install tesseract and poppler")

    pages = convert_from_path(pdf_path, dpi=dpi)
    results = []

    for i, page_image in enumerate(pages, start=1):
        text = pytesseract.image_to_string(page_image, lang=lang)
        results.append(text)
        print(f"  Page {i}/{len(pages)}: {len(text)} characters extracted")

    return results


# ---------------------------------------------------------------------------
# 3. FOIA ZIP archive processing
# ---------------------------------------------------------------------------

def process_foia_zip(
    zip_path: str,
    output_dir: str = "foia_extracted",
    extensions_to_extract: list[str] = None,
) -> dict[str, pd.DataFrame]:
    """
    Many FOIA responses arrive as ZIP archives containing hundreds of files.
    This processes the archive and attempts to read CSVs and Excel files.

    Args:
        zip_path: Path to the ZIP file
        output_dir: Directory to extract non-tabular files to
        extensions_to_extract: File extensions to attempt reading.
                                Defaults to CSV and Excel.

    Returns:
        Dict mapping filename to DataFrame for parseable files
    """
    if extensions_to_extract is None:
        extensions_to_extract = [".csv", ".xlsx", ".xls", ".txt"]

    os.makedirs(output_dir, exist_ok=True)
    dataframes = {}

    with zipfile.ZipFile(zip_path, "r") as zf:
        file_list = zf.namelist()
        print(f"  Archive contains {len(file_list)} files")

        for filename in file_list:
            ext = Path(filename).suffix.lower()

            if ext not in extensions_to_extract:
                # Extract but do not attempt to parse
                zf.extract(filename, output_dir)
                continue

            try:
                with zf.open(filename) as f:
                    content = f.read()

                if ext == ".csv" or ext == ".txt":
                    # Try multiple encodings
                    for encoding in ["utf-8", "latin-1", "cp1252"]:
                        try:
                            df = pd.read_csv(
                                io.BytesIO(content),
                                encoding=encoding,
                                dtype=str,
                                low_memory=False,
                                on_bad_lines="skip",
                            )
                            dataframes[filename] = df
                            print(f"  Parsed: {filename} → {df.shape[0]:,} × {df.shape[1]}")
                            break
                        except UnicodeDecodeError:
                            continue

                elif ext in (".xlsx", ".xls"):
                    df = pd.read_excel(
                        io.BytesIO(content),
                        dtype=str,
                        engine="openpyxl" if ext == ".xlsx" else "xlrd",
                    )
                    dataframes[filename] = df
                    print(f"  Parsed: {filename} → {df.shape[0]:,} × {df.shape[1]}")

            except Exception as e:
                print(f"  Could not parse {filename}: {e}")
                zf.extract(filename, output_dir)

    print(f"\n  Summary: {len(dataframes)} files parsed as DataFrames, "
          f"remainder extracted to {output_dir}/")
    return dataframes


# ---------------------------------------------------------------------------
# 4. Multi-header Excel files from DoD financial/ERP systems
# ---------------------------------------------------------------------------

def read_erp_excel(
    filepath: str,
    sheet_name: str = 0,
    header_rows_to_skip: int = 3,
    footer_rows_to_skip: int = 2,
) -> pd.DataFrame:
    """
    Read Excel exports from DoD ERP systems (GCSS-Army, GFEBS, SABRS, STARS-FL).
    These typically have:
      - Multiple title/metadata rows before the actual column headers
      - A row of merged cells as a section divider
      - Footer rows with totals or disclaimers

    The default parameters match the most common layout (3-row header, 2-row footer).
    Adjust based on the specific export you receive.

    Args:
        filepath: Path to the .xlsx file
        sheet_name: Sheet name or 0-indexed integer
        header_rows_to_skip: Number of rows before the real column header
        footer_rows_to_skip: Number of rows at the bottom to drop

    Returns:
        DataFrame with DoD financial data
    """
    # Read without headers first to see the structure
    raw = pd.read_excel(
        filepath,
        sheet_name=sheet_name,
        header=None,
        dtype=str,
        engine="openpyxl",
    )

    # The real column header row is after the title rows
    column_names = raw.iloc[header_rows_to_skip].tolist()

    # Handle duplicate column names (common in ERP exports with subtotals)
    seen = {}
    clean_names = []
    for name in column_names:
        name_str = str(name).strip() if pd.notna(name) else "unnamed"
        if name_str in seen:
            seen[name_str] += 1
            clean_names.append(f"{name_str}_{seen[name_str]}")
        else:
            seen[name_str] = 0
            clean_names.append(name_str)

    # Extract data rows: after header row, before footer
    data_start = header_rows_to_skip + 1
    data_end = len(raw) - footer_rows_to_skip if footer_rows_to_skip > 0 else len(raw)

    df = raw.iloc[data_start:data_end].copy()
    df.columns = clean_names
    df = df.reset_index(drop=True)

    # Drop rows that are completely empty (section dividers)
    df = df.dropna(how="all")

    # Strip whitespace from string columns
    str_cols = df.select_dtypes(include="object").columns
    df[str_cols] = df[str_cols].apply(lambda col: col.str.strip())

    print(f"  Read {filepath}: {df.shape[0]:,} rows × {df.shape[1]} cols")
    return df


# ---------------------------------------------------------------------------
# 5. Date parsing helpers for government data
# ---------------------------------------------------------------------------

def parse_government_dates(series: pd.Series) -> pd.Series:
    """
    Parse the date format zoo found in government data.
    Handles mixed formats within a single column — common when data
    was manually entered by multiple users over years.

    Common formats encountered:
        14MAR2021       (DDMMMYYYY — common in military systems)
        03/14/2021      (MM/DD/YYYY — Excel default)
        2021-03-14      (ISO 8601 — modern systems)
        20210314        (YYYYMMDD — batch extract format)
        14-MAR-21       (DD-MMM-YY — Oracle legacy)
        Mar 14, 2021    (Long format from Word/PDF)

    Args:
        series: A pandas Series of date strings

    Returns:
        Series of datetime64 values (NaT for unparseable values)
    """
    formats_to_try = [
        "%d%b%Y",       # 14MAR2021
        "%m/%d/%Y",     # 03/14/2021
        "%Y-%m-%d",     # 2021-03-14
        "%Y%m%d",       # 20210314
        "%d-%b-%y",     # 14-MAR-21
        "%d-%b-%Y",     # 14-MAR-2021
        "%b %d, %Y",    # Mar 14, 2021
        "%B %d, %Y",    # March 14, 2021
        "%m-%d-%Y",     # 03-14-2021
        "%Y/%m/%d",     # 2021/03/14
    ]

    result = pd.Series([pd.NaT] * len(series), index=series.index)

    unparsed = series.copy()
    for fmt in formats_to_try:
        mask = result.isna() & unparsed.notna()
        if not mask.any():
            break
        parsed = pd.to_datetime(unparsed[mask], format=fmt, errors="coerce")
        result.loc[parsed.notna()] = parsed[parsed.notna()]

    # Final pass with pandas flexible parser for any remaining values
    still_missing = result.isna() & series.notna()
    if still_missing.any():
        flexible = pd.to_datetime(series[still_missing], errors="coerce", infer_datetime_format=True)
        result.loc[flexible.notna()] = flexible[flexible.notna()]

    failed_count = result.isna().sum() - series.isna().sum()
    if failed_count > 0:
        print(f"  Warning: {failed_count} date values could not be parsed")

    return result


# ---------------------------------------------------------------------------
# Demo / usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Demonstrate the defensive CSV reader on a small synthetic sample
    import tempfile

    sample_csv = """fiscal_year|contract_id|vendor_name|obligation_amount|award_date
2024|N00024-24-C-0001|ACME DEFENSE INC|4250000|14MAR2024
2024|N00024-24-C-0002|BOOZ ALLEN HAMILTON INC|1875000|03/22/2024
2024|N00024-24-C-0003|NULL|750000|20240401
2024|N00024-24-C-0004|RAYTHEON TECHNOLOGIES|N/A|April 15, 2024
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(sample_csv)
        tmp_path = f.name

    print("=== Reading legacy pipe-delimited CSV ===")
    df = read_dod_financial_csv(tmp_path)
    print(df)

    print("\n=== Parsing mixed date formats ===")
    dates_parsed = parse_government_dates(df["award_date"])
    print(dates_parsed)

    os.unlink(tmp_path)
