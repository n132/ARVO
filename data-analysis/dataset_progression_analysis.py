#!/usr/bin/env python3
"""
Dataset Progression Analysis Script
Shows progression of reproducible bugs and bugs with patches over time.
"""

import sqlite3
import json
import re
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime

def extract_date_from_url(url):
    """Extract date from verified_fixed URL format."""
    if not url:
        return None
    
    match = re.search(r'range=(\d{12}):(\d{12})', url)
    if match:
        start_date_str = match.group(1)
        try:
            date = datetime.strptime(start_date_str, '%Y%m%d%H%M')
            return date
        except ValueError:
            return None
    return None

def load_metadata_with_dates(metadata_file):
    """Load metadata and extract dates from verified_fixed URLs."""
    metadata_dict = {}
    
    print(f"Loading metadata from {metadata_file}...")
    with open(metadata_file, 'r') as f:
        for line in f:
            try:
                record = json.loads(line.strip())
                local_id = record.get('localId')
                verified_fixed_url = record.get('verified_fixed')
                
                if local_id and verified_fixed_url:
                    date = extract_date_from_url(verified_fixed_url)
                    if date:
                        metadata_dict[local_id] = {
                            'date': date,
                            'project': record.get('project')
                        }
            except json.JSONDecodeError:
                continue
    
    print(f"Loaded {len(metadata_dict)} records with valid date information")
    return metadata_dict

def get_database_bugs(db_path, metadata_dict):
    """Get reproducible bugs and their patch status from database."""
    print(f"Loading database information from {db_path}...")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT localId, project, reproduced, patch_located
        FROM arvo
        WHERE reproduced = 1
        ORDER BY localId
    """)
    
    db_data = {}
    for row in cursor.fetchall():
        local_id, project, reproduced, patch_located = row
        if patch_located:
            db_data[local_id] = {
                'project': project,
                'reproduced': bool(reproduced),
                'patch_located': bool(patch_located),
                'date': metadata_dict[local_id]['date']
            }
    
    conn.close()
    print(f"Loaded {len(db_data)} patch located bugs from database")
    return db_data

def get_false_positives(fp_db_path, metadata_dict):
    """Get false positive bugs from upstream_false_positives.db."""
    print(f"Loading false positives from {fp_db_path}...")
    
    conn = sqlite3.connect(fp_db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT localId FROM upstream_false_positives
        ORDER BY localId
    """)
    
    fp_data = {}
    for row in cursor.fetchall():
        local_id = row[0]
        # Only include false positives that have metadata (date information)
        if local_id in metadata_dict:
            fp_data[local_id] = {
                'date': metadata_dict[local_id]['date'],
                'project': metadata_dict[local_id]['project']
            }

    conn.close()
    print(f"Loaded {len(fp_data)} false positives with date information")
    return fp_data

def create_progression_data(oss_fuzz_dict, arvo_dict, false_positives_dict) -> pd.DataFrame:
    """Create time series data for dataset progression."""
    print("Creating progression data...")

    oss_fuzz_data = pd.DataFrame.from_dict(oss_fuzz_dict, orient='index')
    arvo_data = pd.DataFrame.from_dict(arvo_dict, orient='index')
    false_positives_data = pd.DataFrame.from_dict(false_positives_dict, orient='index')

    arvo_data_with_patches = arvo_data[arvo_data['patch_located'] == 1]

    # is patch_located in arvo_data all True?
    print(arvo_data['patch_located'].unique())
    print(arvo_data['patch_located'].value_counts())
    print(arvo_data_with_patches['patch_located'].unique())
    print(arvo_data_with_patches['patch_located'].value_counts())

    print("oss_fuzz_data:")
    print(oss_fuzz_data.head())
    print("\narvo_data:")
    print(arvo_data.head())
    print("\nfalse_positives_data:")
    print(false_positives_data.head())
    print("\narvo_data_with_patches:")
    print(arvo_data_with_patches.head())

    oss_fuzz_data.sort_values(by='date', inplace=True)
    arvo_data.sort_values(by='date', inplace=True)
    false_positives_data.sort_values(by='date', inplace=True)
    arvo_data_with_patches.sort_values(by='date', inplace=True)

    oss_fuzz_data['year_month'] = oss_fuzz_data['date'].dt.to_period('M')
    arvo_data['year_month'] = arvo_data['date'].dt.to_period('M')
    false_positives_data['year_month'] = false_positives_data['date'].dt.to_period('M')
    arvo_data_with_patches['year_month'] = arvo_data_with_patches['date'].dt.to_period('M')

    print("\noss_fuzz_data:")
    print(oss_fuzz_data.head())
    print("\narvo_data:")
    print(arvo_data.head())
    print("\nfalse_positives_data:")
    print(false_positives_data.head())
    print("\narvo_data_with_patches:")
    print(arvo_data_with_patches.head())

    oss_fuzz_grouped = oss_fuzz_data.groupby('year_month').size().reset_index(name='total_bugs_from_oss_fuzz')
    arvo_grouped = arvo_data.groupby('year_month').size().reset_index(name='total_bugs_from_arvo')
    fp_grouped = false_positives_data.groupby('year_month').size().reset_index(name='total_false_positives')
    arvo_with_patches_grouped = arvo_data_with_patches.groupby('year_month').size().reset_index(name='total_bugs_from_arvo_with_patches')

    # Find the complete date range across all datasets
    all_dates = []
    if len(oss_fuzz_data) > 0:
        all_dates.append(oss_fuzz_data['year_month'].min())
        all_dates.append(oss_fuzz_data['year_month'].max())
    if len(arvo_data) > 0:
        all_dates.append(arvo_data['year_month'].min())
        all_dates.append(arvo_data['year_month'].max())
    if len(false_positives_data) > 0:
        all_dates.append(false_positives_data['year_month'].min())
        all_dates.append(false_positives_data['year_month'].max())
    if len(arvo_data_with_patches) > 0:
        all_dates.append(arvo_data_with_patches['year_month'].min())
        all_dates.append(arvo_data_with_patches['year_month'].max())

    min_date = min(all_dates)
    max_date = max(all_dates)

    complete_months = pd.period_range(start=min_date, end=max_date, freq='M')
    complete_df = pd.DataFrame({'year_month': complete_months})

    print(f"\nComplete date range: {min_date} to {max_date}")
    print(f"Total months in range: {len(complete_months)}")

    # Merge with complete month range, filling missing months with 0
    oss_fuzz_complete = pd.merge(complete_df, oss_fuzz_grouped, on='year_month', how='left')
    oss_fuzz_complete['total_bugs_from_oss_fuzz'] = oss_fuzz_complete['total_bugs_from_oss_fuzz'].fillna(0)
    
    arvo_complete = pd.merge(complete_df, arvo_grouped, on='year_month', how='left')
    arvo_complete['total_bugs_from_arvo'] = arvo_complete['total_bugs_from_arvo'].fillna(0)
    
    fp_complete = pd.merge(complete_df, fp_grouped, on='year_month', how='left')
    fp_complete['total_false_positives'] = fp_complete['total_false_positives'].fillna(0)

    arvo_with_patches_complete = pd.merge(complete_df, arvo_with_patches_grouped, on='year_month', how='left')
    arvo_with_patches_complete['total_bugs_from_arvo_with_patches'] = arvo_with_patches_complete['total_bugs_from_arvo_with_patches'].fillna(0)

    # Merge all three complete datasets
    db_progression = pd.merge(oss_fuzz_complete, arvo_complete, on='year_month', how='outer')
    db_progression = pd.merge(db_progression, fp_complete, on='year_month', how='outer')
    db_progression = pd.merge(db_progression, arvo_with_patches_complete, on='year_month', how='outer')
    db_progression = db_progression.fillna(0)  # Fill any remaining NaN values with 0

    # Calculate cumulative sums to show total dataset growth over time
    db_progression['cumulative_oss_fuzz'] = db_progression['total_bugs_from_oss_fuzz'].cumsum()
    db_progression['cumulative_arvo'] = db_progression['total_bugs_from_arvo'].cumsum()
    db_progression['cumulative_false_positives'] = db_progression['total_false_positives'].cumsum()
    db_progression['cumulative_arvo_with_patches'] = db_progression['total_bugs_from_arvo_with_patches'].cumsum()

    # Calculate adjusted OSS-Fuzz dataset (original minus false positives)
    db_progression['cumulative_oss_fuzz_adjusted'] = db_progression['cumulative_oss_fuzz'] - db_progression['cumulative_false_positives']

    print("\ndb_progression (complete with all months):")
    print(db_progression.head())
    print(db_progression.tail())
    print(f"\nTotal months in final dataset: {len(db_progression)}")

    return db_progression

def create_size_visualization(db_progression):
    """Create seaborn visualizations showing cumulative dataset growth."""
    print("Creating visualizations...")
    
    # Set seaborn style for a clean, modern look
    sns.set_style("whitegrid")
    sns.set_palette("husl")
    
    # Create the figure (width for LaTeX paper)
    plt.figure(figsize=(10, 5))
    
    # Convert period to datetime for plotting
    db_progression['date'] = db_progression['year_month'].dt.to_timestamp()
    
    # Create the plot with all three cumulative datasets and filled areas
    # First, create the filled areas
    plt.fill_between(db_progression['date'], 
                     db_progression['cumulative_oss_fuzz'], 
                     db_progression['cumulative_oss_fuzz_adjusted'],
                     alpha=0.3, color='red', label='False Positives')
    
    plt.fill_between(db_progression['date'], 
                     db_progression['cumulative_oss_fuzz_adjusted'], 
                     db_progression['cumulative_arvo'],
                     alpha=0.3, color='yellow', label='Unpatched (Adjusted)')
    
    plt.fill_between(db_progression['date'], 
                     0,
                     db_progression['cumulative_arvo'],
                     alpha=0.3, color='green', label='Reproduced with Patches')
    
    # Then add the line plots on top with optimized styling for LaTeX paper
    sns.lineplot(data=db_progression, x='date', y='cumulative_oss_fuzz', 
                linewidth=2, marker='o', markersize=3.5, markeredgewidth=0.5,
                label='OSS-Fuzz Dataset (Original)', color='#1f77b4')
    
    sns.lineplot(data=db_progression, x='date', y='cumulative_oss_fuzz_adjusted', 
                linewidth=2, marker='^', markersize=3.5, markeredgewidth=0.5,
                label='OSS-Fuzz Dataset (Adjusted)', color='#ff7f0e')
    
    sns.lineplot(data=db_progression, x='date', y='cumulative_arvo', 
                linewidth=2, marker='s', markersize=3.5, markeredgewidth=0.5,
                label='ARVO Dataset (with patches)', color='#2ca02c')
    
    # Customize the plot (extra large bold fonts for maximum readability on paper)
    plt.title('Cumulative Dataset Growth Over Time', fontsize=20, fontweight='bold', pad=20)
    plt.xlabel('Year', fontsize=18, fontweight='bold')
    plt.ylabel('Cumulative # of Bugs', fontsize=18, fontweight='bold')
    
    # Format x-axis to show only years (not half-years) for better readability in half-width figure
    plt.gca().xaxis.set_major_locator(plt.matplotlib.dates.YearLocator())
    plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%Y'))
    plt.setp(plt.gca().xaxis.get_majorticklabels(), rotation=0, fontsize=16, fontweight='bold')
    plt.setp(plt.gca().yaxis.get_majorticklabels(), fontsize=16, fontweight='bold')
    
    # Add grid for better readability
    plt.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)
    
    # Customize legend (extra large bold font for maximum readability)
    plt.legend(loc='upper left', fontsize=14, frameon=True, fancybox=True, shadow=False, ncol=2, 
               prop={'weight': 'bold'})
    
    # Add annotations for final values
    if len(db_progression) > 0:
        final_date = db_progression['date'].iloc[-1]
        final_oss_fuzz = db_progression['cumulative_oss_fuzz'].iloc[-1]
        final_oss_fuzz_adjusted = db_progression['cumulative_oss_fuzz_adjusted'].iloc[-1]
        final_arvo = db_progression['cumulative_arvo'].iloc[-1]
        
        # Annotate OSS-Fuzz original final value (extra large bold font for maximum readability)
        plt.annotate(f'Orig: {int(final_oss_fuzz):,}', 
                    xy=(final_date, final_oss_fuzz), 
                    xytext=(8, 20), textcoords='offset points',
                    bbox=dict(boxstyle='round,pad=0.4', facecolor='#b3d9ff', alpha=0.8),
                    arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0.1', color='#1f77b4', lw=2),
                    fontsize=14, fontweight='bold')
        
        # Annotate OSS-Fuzz adjusted final value (extra large bold font for maximum readability)
        plt.annotate(f'Adj: {int(final_oss_fuzz_adjusted):,}', 
                    xy=(final_date, final_oss_fuzz_adjusted), 
                    xytext=(8, 0), textcoords='offset points',
                    bbox=dict(boxstyle='round,pad=0.4', facecolor='#ffd9b3', alpha=0.8),
                    arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0', color='#ff7f0e', lw=2),
                    fontsize=14, fontweight='bold')
        
        # Annotate ARVO final value (extra large bold font for maximum readability)
        plt.annotate(f'ARVO: {int(final_arvo):,}', 
                    xy=(final_date, final_arvo), 
                    xytext=(8, -20), textcoords='offset points',
                    bbox=dict(boxstyle='round,pad=0.4', facecolor='#b3ffb3', alpha=0.8),
                    arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=-0.1', color='#2ca02c', lw=2),
                    fontsize=14, fontweight='bold')
    
    # Adjust layout and save
    plt.tight_layout()
    
    # Save the plot as PDF with high DPI for LaTeX paper
    output_file_pdf = "data-analysis/dataset_progression_analysis.pdf"
    output_file_png = "data-analysis/dataset_progression_analysis.png"
    
    # Save as PDF (vector format, perfect for LaTeX)
    plt.savefig(output_file_pdf, dpi=800, bbox_inches='tight', facecolor='white', 
                format='pdf', backend='pdf')
    
    # Also save as PNG for preview
    plt.savefig(output_file_png, dpi=800, bbox_inches='tight', facecolor='white')
    
    print(f"Visualization saved to {output_file_pdf} (PDF for LaTeX)")
    print(f"Preview saved to {output_file_png}")
    
    # Display summary statistics
    print_summary_statistics(db_progression)
    
    plt.show()
    return plt.gcf()

def print_summary_statistics(db_progression):
    """Print summary statistics for the datasets."""
    print("\n" + "="*70)
    print("DATASET PROGRESSION ANALYSIS SUMMARY")
    print("="*70)
    
    if len(db_progression) == 0:
        print("No data available for analysis.")
        return
    
    # Get date range
    start_date = db_progression['year_month'].iloc[0]
    end_date = db_progression['year_month'].iloc[-1]
    total_months = len(db_progression)
    
    # Get final counts
    final_oss_fuzz = int(db_progression['cumulative_oss_fuzz'].iloc[-1])
    final_oss_fuzz_adjusted = int(db_progression['cumulative_oss_fuzz_adjusted'].iloc[-1])
    final_arvo = int(db_progression['cumulative_arvo'].iloc[-1])
    final_false_positives = int(db_progression['cumulative_false_positives'].iloc[-1])
    
    print(f"Analysis Period: {start_date} to {end_date}")
    print(f"Total Duration: {total_months} months")
    print()
    
    print("DATASET STATISTICS:")
    print(f"  OSS-Fuzz Dataset (Original): {final_oss_fuzz:,} total bugs")
    print(f"  False Positives Identified: {final_false_positives:,} bugs")
    print(f"  OSS-Fuzz Dataset (Adjusted): {final_oss_fuzz_adjusted:,} total bugs")
    print(f"  ARVO Dataset (with patches): {final_arvo:,} total bugs")
    
    if final_oss_fuzz > 0:
        print(f"  False Positive Rate: {final_false_positives/final_oss_fuzz*100:.2f}%")
        print(f"  Patch coverage rate (original): {final_arvo/final_oss_fuzz*100:.2f}%")
        if final_oss_fuzz_adjusted > 0:
            print(f"  Patch coverage rate (adjusted): {final_arvo/final_oss_fuzz_adjusted*100:.2f}%")
    print()
    
    # Calculate growth rates
    if total_months > 1:
        avg_monthly_oss_fuzz = final_oss_fuzz / total_months
        avg_monthly_oss_fuzz_adjusted = final_oss_fuzz_adjusted / total_months
        avg_monthly_arvo = final_arvo / total_months
        avg_monthly_fp = final_false_positives / total_months
        print("AVERAGE MONTHLY GROWTH:")
        print(f"  OSS-Fuzz Dataset (Original): {avg_monthly_oss_fuzz:.1f} bugs per month")
        print(f"  OSS-Fuzz Dataset (Adjusted): {avg_monthly_oss_fuzz_adjusted:.1f} bugs per month")
        print(f"  ARVO Dataset: {avg_monthly_arvo:.1f} bugs per month")
        print(f"  False Positives: {avg_monthly_fp:.1f} bugs per month")
    
    print("\n" + "="*70)

def main():
    """Main function to run the analysis."""
    print("ARVO Dataset Progression Analysis")
    print("="*40)
    
    oss_fuzz_file = 'arvo/NewTracker/metadata.jsonl'
    arvo_file = 'arvo.db'
    false_positives_file = 'upstream_false_positives.db'
    
    try:
        oss_fuzz_dict = load_metadata_with_dates(oss_fuzz_file)
        arvo_dict = get_database_bugs(arvo_file, oss_fuzz_dict)
        false_positives_dict = get_false_positives(false_positives_file, oss_fuzz_dict)
        
        db_size_progression = create_progression_data(oss_fuzz_dict, arvo_dict, false_positives_dict)
        
        print("\nAnalysis completed successfully!")
        
        create_size_visualization(db_size_progression)
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
