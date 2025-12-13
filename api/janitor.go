package main

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StartJanitor initiates the background worker.
// It runs in a separate goroutine and wakes up periodically.
func StartJanitor(db *pgxpool.Pool) {
	// CONFIGURATION: How often does the janitor wake up?
	// For Prod: Every 1 hour is usually fine.
	// For Dev: You might want to shorten this to test it.
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	log.Println("🧹 Janitor started: Watching for stale orders...")

	for range ticker.C {
		runCleanup(db)
	}
}

func runCleanup(db *pgxpool.Pool) {
	// Create a context with timeout so the cleanup doesn't hang forever
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// 1. DEFINE "STALE"
	// Orders older than 24 hours that are still PENDING
	expirationTime := time.Now().Add(-24 * time.Hour)

	// 2. FIND THE CANDIDATES
	rows, err := db.Query(ctx, `
		SELECT id FROM orders 
		WHERE status = 'PENDING_PAYMENT' AND created_at < $1
	`, expirationTime)

	if err != nil {
		log.Printf("🧹 Janitor Error querying orders: %v", err)
		return
	}

	var staleOrderIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err == nil {
			staleOrderIDs = append(staleOrderIDs, id)
		}
	}
	rows.Close() // Close explicitly to free the connection

	if len(staleOrderIDs) == 0 {
		// Nothing to clean today. Go back to sleep.
		return
	}

	log.Printf("🧹 Janitor found %d stale orders. Starting cleanup...", len(staleOrderIDs))

	// 3. CLEAN THEM UP (Transaction)
	for _, orderID := range staleOrderIDs {
		processStaleOrder(ctx, db, orderID)
	}
}

func processStaleOrder(ctx context.Context, db *pgxpool.Pool, orderID int) {
	// We use a transaction because we must do two things AT ONCE:
	// 1. Mark Order as Cancelled
	// 2. Unlock the Products (is_sold = false)

	tx, err := db.Begin(ctx)
	if err != nil {
		log.Printf("🧹 Janitor Tx Error order #%d: %v", orderID, err)
		return
	}
	defer tx.Rollback(ctx) // Rollback if we panic or fail

	// A. Update Order Status
	_, err = tx.Exec(ctx, "UPDATE orders SET status = 'CANCELLED' WHERE id = $1", orderID)
	if err != nil {
		log.Printf("🧹 Janitor Failed to cancel order #%d: %v", orderID, err)
		return
	}

	// B. Release Inventory
	// We update 'is_sold' to false for all products linked to this order
	_, err = tx.Exec(ctx, `
		UPDATE products 
		SET is_sold = false 
		WHERE id IN (SELECT product_id FROM order_items WHERE order_id = $1)
	`, orderID)
	if err != nil {
		log.Printf("🧹 Janitor Failed to release inventory order #%d: %v", orderID, err)
		return
	}

	// C. Commit
	if err := tx.Commit(ctx); err != nil {
		log.Printf("🧹 Janitor Commit Error order #%d: %v", orderID, err)
	} else {
		log.Printf("🧹 Janitor: Order #%d cancelled and inventory released.", orderID)
	}
}
