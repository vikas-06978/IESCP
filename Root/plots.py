import matplotlib
matplotlib.use('Agg')  # Use the Agg backend to avoid Tkinter issues
import matplotlib.pyplot as plt
from flask import current_app
import os

def create_charts(active_users_count, total_sponsor, total_influencer, total_campaigns, total_ad_requests,
                  inactive_users_count, public_campaigns_count, private_campaigns_count, 
                  requets_send_by_sponsors_status, requets_send_by_influencers_status, flagged_entities):
    with current_app.app_context():
        # Define path to save images
        images_dir = os.path.join(current_app.root_path, 'static', 'Images')
        os.makedirs(images_dir, exist_ok=True)

        # Chart 1: Comparison of Active Users, Influencers, and Sponsors
        categories1 = ['Active Users', 'Influencers', 'Sponsors']
        values1 = [active_users_count, total_influencer, total_sponsor]

        plt.figure(figsize=(10, 6))
        plt.plot(categories1, values1, marker='o', linestyle='-', color='blue')
        plt.xlabel('Category')
        plt.ylabel('Count')
        plt.title('Comparison of Active Users, Influencers, and Sponsors')
        plt.grid(True)
        plt.savefig(os.path.join(images_dir, 'comparison1.png'))
        plt.close()

        # Chart 2: Comparison of Campaigns and Ad Requests
        categories2 = ['Campaigns', 'Ad Requests']
        values2 = [total_campaigns, total_ad_requests]

        plt.figure(figsize=(10, 6))
        plt.bar(categories2, values2, color=['purple', 'red'])
        plt.xlabel('Category')
        plt.ylabel('Count')
        plt.title('Comparison of Campaigns and Ad Requests')
        plt.savefig(os.path.join(images_dir, 'comparison2.png'))
        plt.close()

        # Chart 3: Active vs. Inactive Users (Doughnut Chart)
        categories3 = ['Active', 'Inactive']
        values3 = [active_users_count, inactive_users_count]

        plt.figure(figsize=(8, 8))
        plt.pie(values3, labels=categories3, autopct='%1.1f%%', colors=['green', 'red'], startangle=140, wedgeprops=dict(width=0.3))
        plt.title('Active vs. Inactive Users')
        plt.savefig(os.path.join(images_dir, 'active_vs_inactive.png'))
        plt.close()

        # Chart 4: Campaign Visibility (Horizontal Bar Chart)
        categories4 = ['Public', 'Private']
        values4 = [public_campaigns_count, private_campaigns_count]

        plt.figure(figsize=(10, 6))
        plt.barh(categories4, values4, color=['blue', 'orange'])
        plt.xlabel('Count')
        plt.ylabel('Visibility')
        plt.title('Campaign Visibility')
        plt.savefig(os.path.join(images_dir, 'campaign_visibility.png'))
        plt.close()

        # Chart 5: Requests Send by Sponsors Status (Stacked Bar Chart)
        categories5 = ['Pending', 'Approved', 'Rejected']
        values5 = [requets_send_by_sponsors_status['Pending'], requets_send_by_sponsors_status['Approved'], requets_send_by_sponsors_status['Rejected']]

        plt.figure(figsize=(10, 6))
        plt.bar(categories5, values5, color=['yellow', 'green', 'red'])
        plt.xlabel('Status')
        plt.ylabel('Count')
        plt.title('Requests Send by Sponsors Status')
        plt.savefig(os.path.join(images_dir, 'requests_send_by_sponsors_status.png'))
        plt.close()

        # Chart 6: Requests Send by Influencers Status (Stacked Bar Chart)
        categories6 = ['Pending', 'Approved', 'Rejected']
        values6 = [requets_send_by_influencers_status['Pending'], requets_send_by_influencers_status['Approved'], requets_send_by_influencers_status['Rejected']]

        plt.figure(figsize=(10, 6))
        plt.bar(categories6, values6, color=['cyan', 'magenta', 'orange'])
        plt.xlabel('Status')
        plt.ylabel('Count')
        plt.title('Requests Send by Influencers Status')
        plt.savefig(os.path.join(images_dir, 'requests_send_by_influencers_status.png'))
        plt.close()

        # Chart 7: Flagged Entities Analysis (Area Chart)
        categories7 = list(flagged_entities.keys())
        values7 = list(flagged_entities.values())

        plt.figure(figsize=(10, 6))
        plt.fill_between(categories7, values7, color='skyblue', alpha=0.4)
        plt.plot(categories7, values7, marker='o', color='Slateblue', alpha=0.6)
        plt.xlabel('Entity Type')
        plt.ylabel('Count')
        plt.title('Flagged Entities Analysis')
        plt.savefig(os.path.join(images_dir, 'flagged_entities.png'))
        plt.close()
