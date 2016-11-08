//
//  ViewController.swift
//  PacketSniffer
//
//  Created by lijinwei on 2016/11/7.
//  Copyright © 2016年 ljw. All rights reserved.
//

import UIKit
import Foundation

private let kRecentRequestCellIdentifier = "recentRequests"
private let kRecentRequestCachedIdentifier = "requestsCached"

class ViewController: UIViewController,UITableViewDataSource, UITableViewDelegate {
    @IBOutlet var tableview: UITableView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        navigationItem.title = "App Name".localized()
        do {
            try Manager.sharedManager.setup()
        }catch {
            NSLog("Fail to setup manager")
        }
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // Post an empty message so we could attach to packet tunnel process
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    // MARK: - TableView DataSource & Delegate
    @available(iOS 2.0, *)
    public func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: kRecentRequestCellIdentifier, for: indexPath) as! RecentRequestsCell
        cell.setCellInfo(indexPath: indexPath as NSIndexPath)
        return cell
    }
    
    @available(iOS 2.0, *)
    public func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int{
        return 3;
    }
    
    @available(iOS 2.0, *)
    public func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat{
        guard indexPath.row != 2 else {
            return 60
        }
        return 43
    }
    
}


