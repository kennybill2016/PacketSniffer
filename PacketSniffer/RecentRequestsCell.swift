//
//  RecentRequestsCell.swift
//  PacketSniffer
//
//  Created by lijinwei on 2016/11/3.
//  Copyright © 2016年 ljw. All rights reserved.
//

import UIKit

class RecentRequestsCell: UITableViewCell {

    @IBOutlet var startConnectBtn: UIButton!
    @IBOutlet var leftLabel: UILabel!
    @IBOutlet var rightLabel: UILabel!
    
    @IBAction func actionTouchConnect(_ sender: Any) {
        Manager.sharedManager.startVPN()
    }
    
    override func awakeFromNib() {
        super.awakeFromNib()
        // Initialization code
    }

    override func setSelected(_ selected: Bool, animated: Bool) {
        super.setSelected(selected, animated: animated)

        // Configure the view for the selected state
    }

    func setCellInfo(indexPath: NSIndexPath) {
        switch indexPath.row {
        case 2:
            startConnectBtn.isHidden = false
            leftLabel.isHidden = true
            rightLabel.isHidden = true
            
        case 0,1:
            if(indexPath.row==0) {
                leftLabel.text = "开始时间"
                rightLabel.text = "-"
            }
            else {
                leftLabel.text = "持续时间"
                rightLabel.text = "-"
            }
            
            startConnectBtn.isHidden = true
            leftLabel.isHidden = false
            rightLabel.isHidden = false

        default:
            break;
        }
    }
}
